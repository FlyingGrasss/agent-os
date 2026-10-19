//! Concurrency correctness under sustained load.
//!
//! The benchmarks answer "how fast". This file answers "correctly", and it runs
//! in the normal test suite rather than only under `cargo bench` -- a property
//! that only holds when someone remembers to run the benchmarks is not a
//! property.
//!
//! # What is actually being checked
//!
//! Fifty-odd OS threads, each on its own authenticated connection, submitting
//! tasks simultaneously against one daemon that is appending to one real file.
//! Every claim below is a claim about a shared mutable resource under
//! contention:
//!
//! * `FileSink`'s mutex serialises appends, so the hash chain advances once per
//!   record and no two records interleave mid-line.
//! * No record is lost. The expected count is asserted exactly, because "the log
//!   looks fine" and "the log is missing 40 records" are the same thing to a
//!   verifier that only checks the chain.
//! * The inode stays stable, so the rotation guard does not fire spuriously.
//! * Nothing deadlocks: every wait is bounded, so a hang fails the test instead
//!   of stalling CI.
//! * `seq` is ledger-wide: fifty concurrent tasks append records numbered `1`
//!   through `n` with no repeats and no gaps. This used to be false -- the counter
//!   lived in each task's `AuditLog` -- and the test that pinned the old behaviour
//!   was inverted rather than deleted when the counter moved into the shared sink.

use std::io::Write as _;
use std::time::{Duration, Instant};

use agentos_tools::audit::FileIdentity;

#[path = "common/mod.rs"]
mod common;

use common::*;

/// How long a stress run may take before it is treated as a deadlock.
const DEADLOCK_BUDGET: Duration = Duration::from_secs(120);

fn runtime() -> tokio::runtime::Runtime {
    // Multi-thread: the accept loop is spawned onto this runtime, and a
    // current-thread runtime would not poll it while the load generator blocks on
    // synchronous sockets.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

#[test]
fn fifty_concurrent_clients_leave_a_complete_and_intact_ledger() {
    const CLIENTS: usize = 50;
    const TASKS: usize = 50;

    let rt = runtime();
    let dir = scratch_dir("stress-50");
    let harness = rt.block_on(async {
        Harness::start(dir, Box::new(Replay::writing("load.txt")), 128).await
    });

    let identity_before = FileIdentity::of_path(&harness.audit_log).expect("identity");

    // One warm-up batch. The first request pays for socket setup, token parsing
    // and lazy allocation, and folding that into the measurement describes
    // start-up rather than contention.
    let _ = dispatch(&harness, CLIENTS, TASKS);

    let (samples, replies) = dispatch(&harness, CLIENTS, TASKS);

    // Every client got a result and none of them was an error.
    assert_eq!(
        replies.iter().filter(|r| r.contains("\"error\"")).count(),
        0,
        "a task came back as an error under load"
    );

    let stats = percentiles(samples.iter().map(|d| d.as_micros()).collect());
    println!("[stress] {CLIENTS} clients x {TASKS} tasks: {stats}");

    let ledger = harness.ledger();

    // --- the chain survived concurrent appends -------------------------------
    let verified = agentos_tools::chain::verify(&ledger)
        .expect("the chain must survive concurrent appends -- an interleaved write would break it");
    println!(
        "[stress] ledger: {} records, head {}",
        verified.records,
        verified.head_hex()
    );

    // --- no record was lost ---------------------------------------------------
    //
    // One `fs.write` produces one attempt and one outcome, so the count is exact
    // rather than approximate. The warm-up batch is included, because it ran
    // through the same sink.
    let expected = (TASKS * 2 * 2) as u64; // two batches, each TASKS * (attempt + outcome)
    assert_eq!(
        verified.records, expected,
        "records went missing under concurrency: expected {expected}, found {}",
        verified.records
    );

    // --- the inode did not move ----------------------------------------------
    //
    // `same_file`, not `==`: the identity carries size so the sink can catch a
    // `copytruncate`, but the file grows on every append, so comparing the whole
    // struct across a run would compare a number that is supposed to differ. The
    // question here is only whether it is still the same file.
    let identity_after = FileIdentity::of_path(&harness.audit_log).expect("identity");
    assert!(
        identity_before.same_file(&identity_after),
        "the log file was replaced underneath the sink during the run: \
         {identity_before} -> {identity_after}"
    );
    assert!(
        identity_after.size() > identity_before.size(),
        "the ledger did not grow, so this run tested nothing"
    );
}

/// Submit `tasks` requests across `clients` authenticated connections at once.
///
/// Returns every latency and every raw reply so the caller can assert on both;
/// measuring only the timing would let a run of errors look fast.
fn dispatch(
    h: &Harness,
    clients: usize,
    tasks: usize,
) -> (Vec<std::time::Duration>, Vec<String>) {
    let params: Vec<_> = (0..tasks)
        .map(|i| {
            execute_params(
                &format!("write file load-{i}-{}", h.ledger().len()),
                h.write_root(),
            )
        })
        .collect();

    let deadline = Instant::now() + DEADLOCK_BUDGET;
    let mut threads = Vec::new();
    for c_id in 0..clients {
        let params = params.clone();
        let addr = h.addr;
        let token = h.token_hex.clone();
        threads.push(std::thread::spawn(move || {
            let mut stream = connect_authenticated(addr, &token);
            let mut id = 0u64;
            let mut out = Vec::with_capacity(params.len() / clients + 1);
            // Strided, so every client is in flight together rather than each
            // working through a contiguous block that happens to serialise.
            let mut i = c_id;
            while i < params.len() {
                let started = Instant::now();
                let json = serde_json::to_value(&params[i]).expect("params");
                stream
                    .write_all(&request_frame(
                        agentos_cli::daemon::protocol::method::EXECUTE,
                        json,
                        {
                            id += 1;
                            (c_id as u64) << 32 | id
                        },
                    ))
                    .expect("send execute");
                let reply = read_frame(&mut stream).expect("execute reply");
                out.push((started.elapsed(), reply.to_string()));
                i += clients;
            }
            drop(stream);
            out
        }));
    }

    let mut all = Vec::new();
    for t in threads {
        let joined = t.join().expect("a client thread panicked");
        all.extend(joined);
    }
    assert!(
        Instant::now() < deadline,
        "the load generator overran its budget: that is a deadlock, not slow hardware"
    );

    let replies: Vec<String> = all.iter().map(|(_, r)| r.clone()).collect();
    (all.into_iter().map(|(d, _)| d).collect(), replies)
}

/// `seq` is ledger-wide and strictly monotonic, even with eight tasks appending
/// to one log through one shared sink.
///
/// This is the inverted form of the test that used to assert the opposite. The
/// counter now lives in the sink, so the numbers are unique across tasks. A
/// regression that moved it back into `AuditLog` would produce repeats here and
/// nowhere else.
#[test]
fn sequence_numbers_are_ledger_wide_and_strictly_monotonic() {
    const CLIENTS: usize = 8;
    const TASKS: usize = 8;

    let rt = runtime();
    let dir = scratch_dir("stress-seq");
    let harness = rt.block_on(async {
        Harness::start(dir, Box::new(Replay::writing("load.txt")), 64).await
    });
    let _ = dispatch(&harness, CLIENTS, TASKS);

    let seqs: Vec<u64> = harness
        .ledger()
        .lines()
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l.split_once('\t')?.1)
                .ok()?
                .get("seq")?
                .as_u64()
        })
        .collect();

    assert!(!seqs.is_empty(), "no records were written");

    // Exactly 1..=n, in order: no repeats (per-task counters) and no gaps (a
    // number spent on an append that never landed).
    let expected: Vec<u64> = (1..=seqs.len() as u64).collect();
    assert_eq!(
        seqs, expected,
        "sequence numbers must be a ledger-wide total order; a repeated or missing \
         value means the counter is not shared correctly"
    );

    println!(
        "[stress/seq] {} records, seq {}..={}",
        seqs.len(),
        seqs.first().copied().unwrap_or(0),
        seqs.last().copied().unwrap_or(0)
    );
}
