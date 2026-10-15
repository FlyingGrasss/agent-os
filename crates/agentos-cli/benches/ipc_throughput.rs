//! IPC protocol and framing throughput.
//!
//! Four things are measured, in increasing order of what they include:
//!
//! 1. `request_serialise` — building the JSON a client sends.
//! 2. `frame_encode` — the length-prefixed framing the daemon uses. This calls
//!    the daemon's *own* `encode_frame`, not a copy: a benchmark of a
//!    re-implementation reports the re-implementation's cost, and that is the
//!    most common way a benchmark ends up quietly wrong.
//! 3. `auth_handshake` — the whole bearer-token exchange over loopback TCP,
//!    including the 4-byte prefix, the daemon's parse, and the response.
//! 4. `ping_round_trip` / `parallel_clients` — authenticated round trips, one
//!    and then many at once, which is the only number that includes the daemon's
//!    dispatch cost.
//!
//! Framing is deliberately measured on its own as well as inside a round trip.
//! A round trip conflates framing with socket syscalls, JSON parsing, routing,
//! and the semaphore; when that number regresses, this one says whether the wire
//! format or the daemon is responsible.

use std::hint::black_box;
use std::time::Instant;

use agentos_cli::client::AuthToken;
use agentos_cli::daemon::listener;
use agentos_cli::daemon::protocol::{self, ExecuteParams, Grants};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

// `tests/common/mod.rs` is included rather than imported, because Cargo compiles
// each integration target as its own crate and `tests/common` is not a library.
#[path = "../tests/common/mod.rs"]
mod common;

use common::*;

/// A payload shaped like a real `execute` request, so the serialisation cost is
/// representative rather than the cost of serialising `{}`.
fn representative_request() -> ExecuteParams {
    ExecuteParams {
        task: "write a file named throughput.txt whose contents are a number".to_string(),
        grants: Grants {
            hosts: vec!["invoices.example.com".to_string()],
            write_roots: vec!["/srv/agentos/outbox".to_string()],
            send_email: true,
        },
        timeout_secs: 300,
    }
}

/// Shorten criterion's defaults for this whole binary.
///
/// The library default is ~100 samples over 3 seconds *per benchmark*, which for
/// a benchmark whose unit is "spawn 64 threads and do 320 round trips" means
/// minutes per group and a suite nobody runs. A benchmark that is not run
/// measures nothing, so the defaults are traded for repetition counts that still
/// separate the numbers we care about from noise.
fn bench_serialise(c: &mut Criterion) {
    let params = representative_request();

    let mut g = c.benchmark_group("ipc/serialise");
    g.throughput(Throughput::Bytes(
        serde_json::to_vec(&params).unwrap().len() as u64,
    ));
    g.bench_function("execute_params_to_json", |b| {
        b.iter(|| serde_json::to_vec(black_box(&params)).unwrap())
    });

    // And into bytes on the wire, which is what a client actually does.
    g.bench_function("request_to_frame", |b| {
        b.iter(|| frame(black_box(&serde_json::to_vec(&params).unwrap())))
    });
    g.finish();
}

fn bench_framing(c: &mut Criterion) {
    // Three sizes: a ping reply, a typical request, and something near the
    // 64 KiB frame ceiling. The ceiling case is the one worth watching, because
    // that is where a length check or an allocation strategy would show up.
    let small = serde_json::to_vec(&serde_json::json!({"pong": true})).unwrap();
    let medium = serde_json::to_vec(&representative_request()).unwrap();
    let big_payload = "x".repeat(60 * 1024);
    let large = serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "execute", "params": big_payload
    }))
    .unwrap();

    let mut g = c.benchmark_group("ipc/framing");
    for (name, payload) in [
        ("small_16B", &small),
        ("medium", &medium),
        ("near_limit_64KiB", &large),
    ] {
        g.throughput(Throughput::Bytes(payload.len() as u64));
        g.bench_function(format!("encode_{name}"), |b| {
            b.iter(|| listener::encode_frame(black_box(payload)).unwrap())
        });
    }

    // The oversize refusal, which is a security property rather than a speed
    // property, but which sits in the same function and could regress silently.
    g.throughput(Throughput::Elements(1));
    g.bench_function("encode_rejects_oversize", |b| {
        b.iter(|| {
            let too_big = vec![0u8; protocol::MAX_FRAME_BYTES + 1];
            listener::encode_frame(black_box(&too_big)).is_err()
        })
    });
    g.finish();
}

fn bench_handshake(c: &mut Criterion) {
    // Multi-thread, not current-thread, and the difference is not a detail: the daemon's
    // accept loop is spawned onto this runtime, and a current-thread runtime only
    // makes progress while something is inside lock_on. The benchmark body
    // blocks on *synchronous* sockets, so under current-thread the daemon would
    // never be polled, every connection would hang for the full read timeout, and
    // the benchmark would appear to work while measuring a 30-second stall.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = rt.block_on(async {
        Harness::start(scratch_dir("bench-handshake"), Box::new(Replay::reporting()), 4).await
    });

    let addr = harness.addr;
    let token = harness.token_hex.clone();

    // The full exchange a client performs: connect, send the auth frame, read
    // the response. This is the cost of the security boundary, measured rather
// The CPU half of the handshake: what building the auth request and the
    // daemon's reply actually costs. This is the part this codebase owns, and it
    // is what criterion can measure honestly, over and over.
    c.bench_function("ipc/auth_frame_build", |b| {
        b.iter(|| black_box(auth_frame(black_box(&token))))
    });

    let reply = agentos_cli::daemon::protocol::Response::ok(
        serde_json::json!(0),
        serde_json::json!({}),
    );
    c.bench_function("ipc/auth_response_encode", |b| {
        b.iter(|| frame(black_box(&reply.to_bytes())))
    });

    // The whole exchange, over a real socket, measured outside criterion.
    //
    // Not laziness: a handshake *is* a new TCP connection, and criterion's
    // iteration count would open tens of thousands of them. Each leaves a
    // TIME_WAIT behind and Windows' ephemeral range is 16,384 ports, so the
    // benchmark dies with `AddrInUse` (WSAEADDRINUSE from `connect`) rather than
    // reporting a number. Measured once over a fixed count, it is both repeatable
    // and survivable.
    //
    // The number is dominated by the OS TCP handshake rather than by the auth
    // logic, which is precisely why the two CPU benchmarks above sit beside it.
    const HANDSHAKES: u32 = 200;
    let start = Instant::now();
    for _ in 0..HANDSHAKES {
        let mut stream = std::net::TcpStream::connect(addr).expect("connect");
        use std::io::Write;
        stream.write_all(&auth_frame(&token)).expect("send auth");
        read_frame(&mut stream).expect("auth reply");
        drop(stream);
    }
    let each = start.elapsed() / HANDSHAKES;
    eprintln!(
        "[ipc/auth_handshake_tcp] {HANDSHAKES} full handshakes: {each:?} each \
         (connect + auth frame + reply; dominated by the OS TCP handshake)"
    );

    // Reused connection, to separate the handshake from the round trip.
    c.bench_function("ipc/authenticated_ping_round_trip", |b| {
        let mut stream = connect_authenticated(addr, &token);
        b.iter(|| {
            use std::io::Write;
            stream
                .write_all(&black_box(request_frame(
                    protocol::method::PING,
                    serde_json::json!({}),
                    1,
                )))
                .unwrap();
            read_frame(&mut stream).unwrap()
        })
    });

    // Throughput of authenticated round trips, measured as frames/sec so the
    // number reads as what it is rather than as bytes of JSON.
    let mut stream = connect_authenticated(addr, &token);
    let mut g = c.benchmark_group("ipc/throughput");
    g.throughput(Throughput::Elements(1));
    g.bench_function("authenticated_ping_sequential", |b| {
        b.iter(|| {
            use std::io::Write;
            stream
                .write_all(&request_frame(protocol::method::PING, serde_json::json!({}), 1))
                .unwrap();
            read_frame(&mut stream).unwrap()
        })
    });
    g.finish();
}

/// Many connections at once, which is where the accept loop and the per-connection
/// `spawn` actually get exercised. Sequential throughput says nothing about it.
fn bench_parallel(c: &mut Criterion) {
    // Multi-thread, not current-thread, and the difference is not a detail: the daemon's
    // accept loop is spawned onto this runtime, and a current-thread runtime only
    // makes progress while something is inside lock_on. The benchmark body
    // blocks on *synchronous* sockets, so under current-thread the daemon would
    // never be polled, every connection would hang for the full read timeout, and
    // the benchmark would appear to work while measuring a 30-second stall.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = rt.block_on(async {
        Harness::start(scratch_dir("bench-parallel"), Box::new(Replay::reporting()), 64).await
    });
    let addr = harness.addr;
    let token = harness.token_hex.clone();

    // Five pings per client, not twenty-five. Criterion's default sample count
    // multiplies the batch size by ~100, so 25 would mean 160,000 round trips
    // and a benchmark nobody runs. The point is the shape of the throughput
    // curve against concurrency, which five per client shows as clearly as
    // twenty-five and costs a twentieth of the wall time.
    const PINGS: u64 = 5;

    for clients in [8usize, 32, 64] {
        let started = Instant::now();
        let threads = parallel_ping_clients(addr, &token, clients, PINGS);
        let elapsed = started.elapsed();
        let frames = clients as u64 * PINGS;
        eprintln!(
            "[ipc/parallel] {clients:>3} clients x {PINGS} pings: {:.0} frames/sec ({:.1} ms total)",
            frames as f64 / elapsed.as_secs_f64(),
            elapsed.as_secs_f64() * 1000.0
        );
        for t in threads {
            t.join().expect("client thread");
        }

        let mut g = c.benchmark_group(format!("ipc/parallel_{clients}"));
        // Short runs on purpose: a benchmark that takes ten minutes stops being
        // run, and an unrun benchmark measures nothing.
        g.throughput(Throughput::Elements(frames));
        g.bench_function("authenticated_pings", |b| {
            b.iter(|| {
                for t in parallel_ping_clients(addr, &token, clients, PINGS) {
                    t.join().expect("client thread");
                }
            })
        });
        g.finish();
    }
}

/// One OS thread per client, each opening its own authenticated connection.
///
/// Real threads rather than async tasks on purpose: the question is what happens
/// when fifty *processes* connect at once, and fifty tasks on one runtime have a
/// very different syscall and scheduling shape than fifty threads.
fn parallel_ping_clients(
    addr: std::net::SocketAddr,
    token: &str,
    clients: usize,
    pings: u64,
) -> Vec<std::thread::JoinHandle<()>> {
    (0..clients as u64)
        .map(|c_id| {
            let token = token.to_string();
            std::thread::spawn(move || {
                let mut stream = connect_authenticated(addr, &token);
                use std::io::Write;
                for i in 0..pings {
                    stream
                        .write_all(&request_frame(
                            protocol::method::PING,
                            serde_json::json!({}),
                            (c_id * 1000) + i,
                        ))
                        .expect("write ping");
                    read_frame(&mut stream).expect("ping reply");
                }
                // Close before the thread exits rather than at collection: these
                // threads run concurrently, and leaving every socket to linger
                // piles up TIME_WAIT entries until `connect` fails outright.
                drop(stream);
            })
        })
        .collect()
}

/// Reads the token the way a real client does, so the cost of the *client's*
/// discovery path is measured too and not just the server's.
fn bench_token_read(c: &mut Criterion) {
    let dir = scratch_dir("bench-token");
    std::fs::create_dir_all(dir.join("agentosd")).unwrap();
    let path = dir.join("agentosd").join("auth.token");
    let token = agentos_cli::daemon::auth::Token::generate().unwrap();
    std::fs::write(&path, format!("{}\n", token.to_hex())).unwrap();

    let old = std::env::var("AGENTOS_TOKEN_FILE").ok();
    std::env::set_var("AGENTOS_TOKEN_FILE", &path);
    c.bench_function("ipc/client_token_read", |b| {
        b.iter(|| AuthToken::read().expect("read token"))
    });
    match old {
        Some(v) => std::env::set_var("AGENTOS_TOKEN_FILE", v),
        None => std::env::remove_var("AGENTOS_TOKEN_FILE"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// Criterion's defaults are ~100 samples over 3 seconds per benchmark. For the
// parallel groups, where one iteration spawns 64 threads, that is minutes per
// group and a suite nobody runs -- and a benchmark nobody runs measures nothing.
// Ten samples over half a second still separates these numbers from run-to-run
// noise, which is all they are for.
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(std::time::Duration::from_millis(500))
        .warm_up_time(std::time::Duration::from_millis(100));
    targets = bench_serialise,
        bench_framing,
        bench_handshake,
        bench_parallel,
        bench_token_read
}
criterion_main!(benches);
