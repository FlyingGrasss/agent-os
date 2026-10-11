//! Shared daemon state: the ceiling, the backend, and the concurrency limit.
//!
//! # Why the backend is behind an async mutex
//!
//! `Backend::complete` takes `&mut self`, so a model call cannot be shared across
//! concurrent tasks without serialisation. Rather than pool one backend per worker
//! and let each pull a distinct model into memory, the daemon holds one.
//!
//! The consequence to be explicit about: **task execution is serialised on the
//! model.** The concurrency limit still bounds how many requests are *in flight*,
//! but only one can be inside `Session::run` at a time. That is a throughput
//! property, not a safety one -- no two tasks share a `PolicyHost`, a grant, or an
//! audit record -- and the alternative (one backend per worker) is worse here,
//! because the host has roughly 6 GB of free memory and a 3B model is 2 GB of it.
//!
//! # Why the guard is owned rather than borrowed
//!
//! The run happens on a blocking thread, so it cannot hold a `std::sync::MutexGuard`
//! borrowed from a future that `.await`s. `tokio::sync::Mutex::lock_owned` returns
//! an `OwnedMutexGuard` that is `Send` and owns its reference, so it moves across
//! the `spawn_blocking` boundary and drops there when the task ends. The
//! alternative -- a `Box::leak` handover slot -- looks simpler and leaks once per
//! request rather than once per process, which is the kind of defect that only
//! shows up under load.

use std::path::PathBuf;
use std::sync::Arc;

use agentos_infer::Backend;

use super::executor::{SharedClock, SharedSink};

use super::executor;
use super::grants::Ceiling;
use super::protocol::{codes, ErrorBody, ExecuteParams, Info, TaskOutcome};

/// Everything a request handler needs, owned by the daemon.
pub struct DaemonState {
    /// The operator's ceiling. Never derived from a request.
    pub ceiling: Ceiling,
    /// The model. Held in an async mutex because `complete` needs `&mut` and the
    /// run happens on a blocking thread.
    backend: Arc<tokio::sync::Mutex<Box<dyn Backend + Send>>>,
    /// Where the append-only audit log goes. Shared, because invariant I6 says
    /// every action is recorded before it executes and a per-task log would let a
    /// later task's records be separated from an earlier task's evidence.
    audit_sink: SharedSink,
    clock: SharedClock,
    /// The model name, kept for `info`.
    pub model: String,
    /// How many requests may be in flight at once.
    pub max_concurrent_tasks: usize,
    /// Bounds in-flight requests.
    permits: Arc<tokio::sync::Semaphore>,
}

impl DaemonState {
    pub fn new(
        ceiling: Ceiling,
        backend: Box<dyn Backend + Send>,
        audit_sink: SharedSink,
        clock: SharedClock,
        model: String,
        max_concurrent_tasks: usize,
    ) -> Self {
        Self {
            ceiling,
            backend: Arc::new(tokio::sync::Mutex::new(backend)),
            audit_sink,
            clock,
            model,
            max_concurrent_tasks,
            permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_tasks.max(1))),
        }
    }

    /// Run one task to completion.
    ///
    /// The semaphore is acquired first, so a burst queues on concurrency rather
    /// than piling up contending for the backend lock they cannot proceed past
    /// anyway. The permit is dropped when this returns, including on the timeout
    /// path -- the blocking task outlives the timeout, and holding a permit for a
    /// task nobody is waiting on would slowly starve the daemon.
    pub async fn run(&self, params: ExecuteParams) -> Result<TaskOutcome, ErrorBody> {
        let _permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .expect("the daemon's semaphore is never closed");

        let timeout = params.clamped_timeout();

        // The whole run is blocking: `Session::run` is synchronous, the planner
        // makes a synchronous request to Ollama, and the tools do blocking file and
        // socket I/O. Running it on the async runtime's own threads would stall
        // every other connection for the duration of a model call, which is most
        // of a second. `spawn_blocking` moves it to a pool sized for blocking work.
        let mut backend = self
            .backend
            .clone()
            .lock_owned()
            .await;
        let ceiling = self.ceiling.clone();
        let sink = self.audit_sink.clone();
        let clock = self.clock.clone();

        let handle = tokio::task::spawn_blocking(move || {
            executor::run_task(backend.as_mut(), params, &ceiling, sink, clock)
        });

        match tokio::time::timeout(timeout, handle).await {
            Ok(Ok(result)) => result,
            // The blocking task panicked rather than returning an error. The
            // backend guard drops with it, so the lock is released and the next
            // task is not poisoned.
            Ok(Err(join_error)) => Err(ErrorBody::internal(format!(
                "the task thread ended badly: {join_error}"
            ))),
            Err(_) => {
                // The blocking task is *not* cancelled -- `spawn_blocking` tasks
                // cannot be aborted -- so it may still be running and may still
                // hold the backend. The timeout therefore abandons the result
                // rather than the work, and the next task waits for the backend
                // rather than racing a still-live one. That wait is bounded by the
                // abandoned task, not by this deadline, which is the honest
                // behaviour: a slow task holds the machine rather than being
                // killed mid-audit-write.
                Err(ErrorBody {
                    code: codes::INVALID_PARAMS,
                    message: format!("the task exceeded its {}s limit", timeout.as_secs()),
                    data: Some(serde_json::json!({ "kind": "timeout" })),
                })
            }
        }
    }

    /// Report what this daemon is and can do.
    pub fn info(&self) -> Info {
        executor::describe(&self.model, &self.ceiling, self.max_concurrent_tasks)
    }
}

/// Where a daemon's audit records go when nothing says otherwise.
pub fn default_audit_path() -> PathBuf {
    PathBuf::from("agentosd-audit.log")
}