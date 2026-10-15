//! Concurrent task dispatch: latency distribution under simultaneous load.
//!
//! Criterion reports a mean and a median. That is not enough here, because the
//! question is not "how long does a task take on average" but "what happens to
//! the slowest tenth when fifty arrive at once" — so every run collects the full
//! latency sample and prints p50/p95/p99 itself.
//!
//! What is under measurement is the whole path a request takes: framing,
//! authentication, grant narrowing, the planner, the interpreter, the policy
//! engine, and `FileSink::append` with its mutex and its `sync_data`. The model
//! is replayed so the run is deterministic and does not need a 2 GB download; it
//! is never the thing being measured.

use std::hint::black_box;
use std::time::{Duration, Instant};

use agentos_cli::daemon::protocol::{self, ExecuteParams};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};

#[path = "../tests/common/mod.rs"]
mod common;

use common::*;

/// One authenticated connection, kept open for the whole run.
struct Session {
    stream: std::net::TcpStream,
    next_id: u64,
}

impl Session {
    fn execute(&mut self, params: &ExecuteParams) -> serde_json::Value {
        use std::io::Write;
        self.next_id += 1;
        let json = serde_json::to_value(params).expect("params");
        self.stream
            .write_all(&request_frame(protocol::method::EXECUTE, json, self.next_id))
            .expect("send execute");
        read_frame(&mut self.stream).expect("execute reply")
    }

    fn execute_timed(&mut self, params: &ExecuteParams) -> (Duration, serde_json::Value) {
        let start = Instant::now();
        let reply = self.execute(params);
        (start.elapsed(), reply)
    }
}

/// Submit `tasks` requests across `clients` connections at once, returning every
/// latency in the order observed.
fn dispatch_concurrently(h: &Harness, clients: usize, tasks: usize) -> Vec<Duration> {
    let params: Vec<ExecuteParams> = (0..tasks)
        .map(|i| execute_params(&format!("write file load-{i}.txt"), h.write_root()))
        .collect();

    let mut threads = Vec::new();
    for c_id in 0..clients {
        let params = params.clone();
        let addr = h.addr;
        let token = h.token_hex.clone();
        threads.push(std::thread::spawn(move || {
            let mut session = Session {
                stream: connect_authenticated(addr, &token),
                next_id: 0,
            };
            // Strided so every client is working, rather than each running a
            // contiguous block that happens to serialise on one core.
            let mut out = Vec::with_capacity(params.len() / clients + 1);
            let mut i = c_id;
            while i < params.len() {
                let (d, reply) = session.execute_timed(&params[i]);
                assert!(
                    reply.get("result").is_some(),
                    "task {i} did not produce a result: {reply}"
                );
                out.push(d);
                i += clients;
            }
            out
        }));
    }

    let mut all = Vec::new();
    for t in threads {
        all.extend(t.join().expect("client thread did not panic"));
    }
    all
}

fn summarise(samples: &[Duration]) -> Percentiles {
    percentiles(samples.iter().map(|d| d.as_micros()).collect())
}

/// Shorten criterion's defaults for this whole binary.
///
/// Criterion's default is ~100 samples over 3 seconds per benchmark, multiplied
/// by a batch that dispatches a hundred tasks across fifty threads. That is
/// minutes per group, and a benchmark nobody runs measures nothing. These
/// settings still separate the numbers that matter from run-to-run noise.
/// The headline measurement: how the distribution moves as concurrency rises.
fn bench_scaling(_c: &mut Criterion) {
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

    for clients in [1usize, 8, 32, 50, 64] {
        let dir = scratch_dir(&format!("scale-{clients}"));
        let harness = rt.block_on(async {
            Harness::start(
                dir,
                Box::new(Replay::writing("load.txt")),
                // Permits at or above the client count, so the concurrency
                // limiter does not silently serialise the run and make the
                // numbers describe a queue rather than parallel dispatch.
                128,
            )
            .await
        });

        // One untimed warm-up: the first request pays for socket setup, token
        // parsing, and lazy allocation, and folding that into the distribution
        // would describe start-up cost rather than dispatch cost.
        let warm = dispatch_concurrently(&harness, clients, clients);
        let warm_stats = summarise(&warm);
        eprintln!("[dispatch/warmup clients={clients}] {warm_stats}");

        let samples = dispatch_concurrently(&harness, clients, clients);
        let stats = summarise(&samples);
        eprintln!(
            "[dispatch] clients={clients:>3} tasks={:>3}  {stats}",
            samples.len()
        );
        drop(harness);
    }
}

/// Sustained load: enough tasks that p99 is not an artefact of a handful of
/// samples, timed as a batch so criterion still reports a stable total.
fn bench_sustained(c: &mut Criterion) {
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
    let root = scratch_dir("sustained");
    let harness = rt.block_on(async {
        Harness::start(root, Box::new(Replay::writing("load.txt")), 128).await
    });

    let _warm = dispatch_concurrently(&harness, 50, 50);

    let mut g = c.benchmark_group("dispatch/sustained_50_clients");
    // 100 tasks is enough for p99 to mean something, and short enough that the
    // whole benchmark runs in CI. A stress number that takes ten minutes to
    // produce is a stress number nobody produces.
    g.throughput(Throughput::Elements(100));
    g.bench_function("100_task_dispatch", |b| {
        b.iter(|| {
            let samples = dispatch_concurrently(black_box(&harness), 50, 100);
            let stats = summarise(&samples);
            black_box(stats)
        })
    });
    g.finish();

    // Percentiles are printed outside criterion as well, because criterion's own
    // output has no place to put them and they are the number actually wanted.
    let samples = dispatch_concurrently(&harness, 50, 100);
    let stats = summarise(&samples);
    eprintln!("[dispatch/sustained] 100 tasks over 50 clients: {stats}");
    let ledger = harness.ledger();
    eprintln!(
        "[dispatch/sustained] ledger: {} records, chain {}",
        ledger.lines().count(),
        if agentos_tools::chain::verify(&ledger).is_ok() {
            "intact"
        } else {
            "BROKEN"
        }
    );
}

/// The cost of authentication itself, isolated: what the security boundary
/// charges a client per connection.
fn bench_auth_cost(c: &mut Criterion) {
    // Multi-thread, not current-thread, and the difference is not a detail: the
    // daemon's accept loop is spawned onto this runtime, and a current-thread
    // runtime only makes progress while something is inside a block_on call. The
    // benchmark body blocks on *synchronous* sockets, so under current-thread the
    // daemon would never be polled, every connection would hang for the full read
    // timeout, and the benchmark would appear to work while measuring a
    // 30-second stall.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = rt.block_on(async {
        Harness::start(scratch_dir("auth-cost"), Box::new(Replay::reporting()), 64).await
    });

    // Fixed counts, measured outside criterion, for the same reason as the
    // handshake bench in `ipc_throughput`: one connection per iteration across
    // thousands of iterations exhausts the ephemeral port range, and the run then
    // dies in `read_frame` instead of reporting a number.
    const N: u32 = 200;

    let started = Instant::now();
    for _ in 0..N {
        drop(connect_authenticated(harness.addr, &harness.token_hex));
    }
    let authed = started.elapsed() / N;

    let started = Instant::now();
    for _ in 0..N {
        drop(std::net::TcpStream::connect(harness.addr).expect("connect"));
    }
    let bare = started.elapsed() / N;

    let overhead = authed.saturating_sub(bare);
    let pct = if bare.as_nanos() == 0 {
        0.0
    } else {
        overhead.as_nanos() as f64 / bare.as_nanos() as f64 * 100.0
    };
    eprintln!(
        "[dispatch/auth] authenticated connect {authed:?} vs bare connect {bare:?} \
         -- the token exchange adds {overhead:?} ({pct:.0}% of the connect)",
    );

    // The reusable part criterion can measure honestly: a round trip on a
    // connection that already exists.
    let mut stream = connect_authenticated(harness.addr, &harness.token_hex);
    c.bench_function("dispatch/authenticated_ping", |b| {
        b.iter(|| {
            use std::io::Write;
            stream
                .write_all(&request_frame(
                    agentos_cli::daemon::protocol::method::PING,
                    serde_json::json!({}),
                    1,
                ))
                .unwrap();
            read_frame(&mut stream).unwrap()
        })
    });
}

// Criterion's defaults are ~100 samples over 3 seconds per benchmark, multiplied
// by a batch that dispatches a hundred tasks across fifty threads. That is
// minutes per group. Ten samples over half a second still separates the
// distributions that matter from run-to-run noise.
criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_millis(500))
        .warm_up_time(Duration::from_millis(100));
    targets = bench_scaling, bench_sustained, bench_auth_cost
}
criterion_main!(benches);
