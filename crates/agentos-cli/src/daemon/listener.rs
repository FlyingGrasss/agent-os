//! The IPC listener: framing, dispatch, and the accept loop.
//!
//! # Transport
//!
//! A Unix domain socket on Unix, a TCP socket bound to `127.0.0.1` elsewhere.
//! Both carry the same 4-byte big-endian length prefix and the same JSON payload,
//! so the protocol does not vary by platform and a client written for one works
//! against the other.
//!
//! # The TCP bind address is not a formality
//!
//! `bind` is called with an address that has been checked to be loopback, and
//! `serve` will not start otherwise. Binding `0.0.0.0` would expose the one
//! process in the system that holds write authority to the network, and since
//! this build has no authentication on the socket, that would be handing the
//! machine away. The check is a hard refusal rather than a warning because a
//! daemon that starts with a warning is a daemon someone will deploy with the
//! warning scrolled past.
//!
//! # Framing is bounded in both directions
//!
//! The reader refuses a frame larger than [`MAX_FRAME_BYTES`] rather than
//! allocating for it, and the writer refuses to emit one larger than either. A
//! client cannot make this process reserve memory without limit, and a client
//! cannot silently receive a truncated message.

use std::io;
#[cfg(unix)]
use std::path::Path;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
#[cfg(test)]
use bytes::Buf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use super::executor;
use super::protocol::{ErrorBody, ExecuteParams, Request, Response, MAX_FRAME_BYTES};
use super::state::DaemonState;

/// Length prefix width, in bytes.
const PREFIX: usize = 4;

/// Split a complete frame off the front of `src`, if one is present.
///
/// Returns `Ok(None)` when the frame is not yet complete, which is not an error: a
/// length prefix plus a partial body is exactly what a socket read produces, and
/// the caller should read more. A *length* that cannot be believed is a different
/// thing, and is refused before any allocation happens.
///
/// The production loop does not call this. It reads the prefix and the body
/// separately with [`read_exact`], because once the length is known there is
/// nothing to buffer and refill -- it waits for exactly the bytes the header
/// promised. This function is a second, independent implementation of the same
/// framing rule, and it exists so the tests check the *rule* rather than
/// re-deriving it from the loop. If the two ever disagree, one of the tests below
/// fails.
#[cfg(test)]
pub(crate) fn decode_frame(src: &mut BytesMut) -> Result<Option<Bytes>, io::Error> {
    if src.len() < PREFIX {
        return Ok(None);
    }
    let mut len_bytes = [0u8; PREFIX];
    len_bytes.copy_from_slice(&src[..PREFIX]);
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"),
        ));
    }
    if src.len() < PREFIX + len {
        return Ok(None);
    }
    src.advance(PREFIX);
    Ok(Some(src.split_to(len).freeze()))
}

/// Frame a payload for the wire.
fn encode_frame(payload: &[u8]) -> Result<BytesMut, io::Error> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("response of {} bytes exceeds the {MAX_FRAME_BYTES}-byte limit", payload.len()),
        ));
    }
    let mut out = BytesMut::with_capacity(PREFIX + payload.len());
    out.put_u32(payload.len() as u32);
    out.put_slice(payload);
    Ok(out)
}

/// Read exactly `n` bytes.
async fn read_exact<S: AsyncRead + Unpin>(stream: &mut S, n: usize) -> io::Result<Bytes> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

/// Serve one already-accepted connection until the peer stops sending.
///
/// Each frame is handled independently: a request that fails is answered with an
/// error response and the connection stays open. Closing on the first bad frame
/// would turn a client bug into an outage, and the failure is not the client's
/// fault in the interesting cases -- an unusable plan is the model's.
async fn serve_connection<S>(mut stream: S, state: Arc<DaemonState>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let prefix = match read_exact(&mut stream, PREFIX).await {
            Ok(b) => b,
            // A clean close between frames is how a client says goodbye.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
            Err(_) => return,
        };

        let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
        if len > MAX_FRAME_BYTES {
            // Refuse and close. There is no way to resynchronise a length-prefixed
            // stream after a bad length without guessing where the next frame
            // starts, and guessing on a stream carrying authority requests is not
            // a risk worth taking.
            let _ = write_response(
                &mut stream,
                &Response::err(
                    serde_json::Value::Null,
                    ErrorBody::parse_error(format!(
                        "frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"
                    )),
                ),
            )
            .await;
            return;
        }

        let body = match read_exact(&mut stream, len).await {
            Ok(b) => b,
            Err(_) => return,
        };

        let response = handle_frame(&body, &state).await;
        if write_response(&mut stream, &response).await.is_err() {
            return;
        }
    }
}

async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &Response,
) -> io::Result<()> {
    let framed = encode_frame(&response.to_bytes())?;
    stream.write_all(&framed).await?;
    stream.flush().await
}

/// Decode one frame, dispatch it, and produce the response.
///
/// Never returns an error: every failure becomes an error *response*, because a
/// client that cannot parse the answer is no more able to act than one that got
/// none, and a silent close is indistinguishable from a crash.
pub async fn handle_frame(body: &[u8], state: &DaemonState) -> Response {
    let request: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => {
            return Response::err(
                serde_json::Value::Null,
                ErrorBody::parse_error(format!("not a valid request: {e}")),
            )
        }
    };

    let id = request.id.clone();

    if request.jsonrpc != "2.0" {
        return Response::err(
            id,
            ErrorBody::invalid_request(format!(
                "jsonrpc must be \"2.0\", got {:?}",
                request.jsonrpc
            )),
        );
    }

    match request.method.as_str() {
        super::protocol::method::PING => Response::ok(id, serde_json::json!({ "pong": true })),

        super::protocol::method::INFO => Response::ok(
            id,
            serde_json::to_value(executor::describe(
                &state.model,
                &state.ceiling,
                state.max_concurrent_tasks,
            ))
            .unwrap_or(serde_json::Value::Null),
        ),

        super::protocol::method::EXECUTE => {
            let params: ExecuteParams = match serde_json::from_value(request.params) {
                Ok(p) => p,
                Err(e) => {
                    return Response::err(
                        id,
                        ErrorBody::invalid_params(format!("bad execute params: {e}")),
                    )
                }
            };
            match state.run(params).await {
                Ok(outcome) => {
                    let value = serde_json::to_value(outcome).unwrap_or_else(|e| {
                        serde_json::json!({
                            "kind": "failed",
                            "message": format!("outcome could not be serialised: {e}"),
                            "policy_denied": false,
                        })
                    });
                    Response::ok(id, value)
                }
                Err(e) => Response::err(id, e),
            }
        }

        other => Response::err(
            id,
            ErrorBody::method_not_found(format!("no method named {other:?}")),
        ),
    }
}

/// Bind and serve on a Unix domain socket.
///
/// The socket is created with mode `0600` where the platform supports it, so that
/// only the account running the daemon can open it. A world-writable control
/// socket in `/tmp` would be equivalent to giving every local user the daemon's
/// authority.
#[cfg(unix)]
pub async fn serve_unix(
    path: &Path,
    state: Arc<DaemonState>,
) -> io::Result<tokio::task::JoinHandle<()>> {
    use std::os::unix::fs::PermissionsExt;

    // A stale socket file from a previous run would make `bind` fail with
    // "address in use" even though nothing is listening. Removing it is safe only
    // because the path is the daemon's own, configured at startup.
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;

    Ok(tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let state = state.clone();
            tokio::spawn(async move {
                serve_connection(stream, state).await;
            });
        }
    }))
}

/// Bind a TCP listener, refusing anything that is not loopback.
///
/// Binding is split from accepting so the caller can announce the address *after*
/// the bind has succeeded. Printing it before would put a "listening on 0.0.0.0"
/// line in the log of a process that never listened on it, and that is exactly
/// the sort of line someone later reads to conclude the daemon was exposed.
///
/// `addr` has already been parsed into a `SocketAddr`; the check is on that value,
/// not on the string it came from, so a hostname cannot smuggle a wildcard past it.
pub async fn bind_tcp(addr: std::net::SocketAddr) -> io::Result<TcpListener> {
    if !addr.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to bind {addr}: the daemon holds write authority and its socket \
                 is unauthenticated, so it may only listen on loopback"
            ),
        ));
    }
    TcpListener::bind(addr).await
}

/// Accept connections on an already-bound listener.
pub async fn accept_tcp(listener: TcpListener, state: Arc<DaemonState>) -> io::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        // Belt and braces: the bind address was checked, and the accepted peer's
        // address is checked again. A socket bound to loopback cannot normally
        // receive a non-loopback peer, so this is the check that turns an
        // assumption into a fact at the moment it matters.
        if !peer.ip().is_loopback() {
            continue;
        }
        let state = state.clone();
        tokio::spawn(async move {
            serve_connection(stream, state).await;
        });
    }
}

/// Frame a payload. Exposed for tests.
#[cfg(test)]
pub(crate) fn encode_frame_for_test(payload: &[u8]) -> io::Result<BytesMut> {
    encode_frame(payload)
}