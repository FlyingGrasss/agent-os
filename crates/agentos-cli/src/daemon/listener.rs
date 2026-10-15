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

use super::auth::{self, AuthParams, Token, AUTH_METHOD};
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
///
/// `pub` so the throughput benchmark measures *this* function rather than a
/// copy of it. A benchmark of a re-implementation reports the re-implementation's
/// cost, which is the most common way a benchmark ends up lying: the copy
/// diverges, the number stays on the wall, and nothing notices. This is a pure
/// function with no invariants attached, so widening its visibility costs nothing.
pub fn encode_frame(payload: &[u8]) -> Result<BytesMut, io::Error> {
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

/// Read one length-prefixed frame.
///
/// `Ok(None)` means the peer closed cleanly between frames, which is how a client
/// says goodbye and is not an error. A length beyond [`MAX_FRAME_BYTES`] is
/// refused before anything is allocated for it, and the caller closes: there is no
/// way to resynchronise a length-prefixed stream after a bad length without
/// guessing where the next frame begins, and guessing on a stream that carries
/// authority requests is not a risk worth taking.
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<Bytes>, io::Error> {
    let prefix = match read_exact(stream, PREFIX).await {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    };

    let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME_BYTES}-byte limit"),
        ));
    }

    match read_exact(stream, len).await {
        Ok(body) => Ok(Some(body)),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(e) => Err(e),
    }
}

/// Require a valid `auth` frame before anything else.
///
/// # Why this is a gate and not a method
///
/// If `auth` were dispatched alongside `ping` and `execute`, then the order of
/// frames would decide whether a request was honoured, and the connection state
/// that enforces it would live inside the same `match` as the routing. That is a
/// mistake waiting to happen: adding a branch to the dispatcher would silently
/// make unauthenticated dispatch reachable.
///
/// So authentication happens before the dispatch loop exists. Nothing is routed
/// until this returns `Ok`, and on `Err` the connection is answered and closed.
///
/// # Why a failed handshake closes
///
/// Answering and continuing would leave an unauthenticated channel with a
/// working path. Guessing a 256-bit token is infeasible either way, but the close
/// is the shape that says "this connection was never established", and it means an
/// attacker gets one guess per connection rather than one per frame.
///
/// # Why success sends a response
///
/// The client must receive an acknowledgment for its `auth` request before it can
/// send anything else. Without it, the client blocks forever waiting for a reply
/// that never comes, and the connection appears to hang. This function sends the
/// success response before returning.
async fn authenticate<S>(stream: &mut S, token: &Token) -> Result<(), ErrorBody>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let frame = match read_frame(stream).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Err(ErrorBody::unauthorized(
                "closed before authenticating".to_string(),
            ))
        }
        Err(e) => {
            // A framing error before the handshake cannot be attributed to a bad
            // token, and saying so would let a client distinguish "your framing is
            // wrong" from "your token is wrong". Both are refusals.
            return Err(ErrorBody::unauthorized(format!(
                "could not read the authentication frame: {e}"
            )));
        }
    };

    let request: Request = match serde_json::from_slice(&frame) {
        Ok(r) => r,
        Err(_) => {
            return Err(ErrorBody::unauthorized(
                "the first frame was not a valid request".to_string(),
            ))
        }
    };

    if request.jsonrpc != "2.0" || request.method != AUTH_METHOD {
        return Err(ErrorBody::unauthorized(format!(
            "the first frame must be a `{AUTH_METHOD}` request"
        )));
    }

    let params: AuthParams = match serde_json::from_value(request.params) {
        Ok(p) => p,
        Err(_) => {
            return Err(ErrorBody::unauthorized(
                "the authentication request was malformed".to_string(),
            ))
        }
    };

    auth::verify(token, &params.token)
        .map_err(|_| ErrorBody::unauthorized("authentication failed".to_string()))?;

    // Send a success response. The client must receive this before it can send
    // anything else. A minimal `{"result":{}}` is enough - the protocol doesn't
    // prescribe any auth payload beyond success/failure, and the test suite
    // expects exactly this.
    let success = Response::ok(request.id, serde_json::json!({}));
    write_response(stream, &success).await
        .map_err(|_| ErrorBody::internal("could not send the authentication response"))?;
    Ok(())
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
    // The gate. Everything below runs only for a connection that presented the
    // right token, and a wrong token ends the connection here rather than being
    // answered and then served.
    if let Err(error) = authenticate(&mut stream, state.token()).await {
        let _ = write_response(
            &mut stream,
            &Response::err(serde_json::Value::Null, error),
        )
        .await;
        return;
    }

    loop {
        let body = match read_frame(&mut stream).await {
            Ok(Some(b)) => b,
            // A clean close between frames is how a client says goodbye.
            Ok(None) => return,
            Err(e) => {
                let _ = write_response(
                    &mut stream,
                    &Response::err(
                        serde_json::Value::Null,
                        ErrorBody::parse_error(format!("framing error: {e}")),
                    ),
                )
                .await;
                return;
            }
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
                state.requires_auth(),
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

/// Serve a Unix-domain connection.
///
/// # Why this does not authenticate
///
/// The socket is created `0600` and the *kernel* enforces that at `connect` time,
/// before a byte is exchanged. That is a stronger control than a token file: it
/// cannot be copied, cannot go stale, and cannot be replayed from another user's
/// session. Requiring a token here would add a second credential to get wrong in
/// exchange for no additional security.
///
/// The TCP path is different because loopback has no such property — any local
/// user can connect — which is exactly the gap [`auth`] fills.
#[cfg(unix)]
async fn serve_unix_connection<S>(mut stream: S, state: Arc<DaemonState>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    loop {
        let body = match read_frame(&mut stream).await {
            Ok(Some(b)) => b,
            Ok(None) => return,
            Err(_) => return,
        };

        let response = handle_frame(&body, &state).await;
        if write_response(&mut stream, &response).await.is_err() {
            return;
        }
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
    // Checked back after the bind rather than assumed. `bind` creates the file
    // under the process umask, so a permissive umask would otherwise produce a
    // socket any local user could connect to -- and this daemon's authority does
    // not go out to whoever can open a socket.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to serve on {}: the socket is mode {mode:o}, so other local \
                 users could connect",
                path.display()
            ),
        ));
    }

    Ok(tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => continue,
            };
            let state = state.clone();
            tokio::spawn(async move {
                serve_unix_connection(stream, state).await;
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