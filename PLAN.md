# AgentOS plan

Status against the original seven-phase roadmap. Checked boxes mean built **and**
covered by a test that would fail if the property broke. Anything unchecked with
a note means something was built but the phase's exit criterion is not met.

Last updated to match commit `a5559c5`, which is the last commit that changed
code.

**Verification for this update:** `cargo test --workspace` and
`cargo clippy --all-targets` both clean on Linux (`x86_64-unknown-linux-gnu`)
and on the Windows host — 407 tests on Linux, 316 on Windows, zero failures,
zero clippy warnings on either. The gap between the two counts is the Linux-only
sandbox, quarantine, and seccomp suites.

---

## Where the six invariants stand

| # | Invariant | State | Enforced where |
|---|---|---|---|
| I1 | No untrusted bytes in the Controller's prompt | **Partial** | `Trusted<T>` is a separate type, so prompt assembly accepts nothing else. `leak.rs` counts every slot fill and the gate is the count being exactly zero. Still partial: there is no end-to-end prompt assembly to run the counter over a real task. |
| I2 | Extractor has no tools, network, or filesystem | **Done** | `agentos-quarantine`: `SandboxedExtractor` forks, applies Landlock, applies seccomp, and only then starts the engine. Demonstrated against a real kernel by 18 escape tests, not argued from configuration. |
| I3 | Labels propagate through all operations | **Done** | `Val::map`/`zip`/`map_with_label`, interpreter's field/len/extract/iteration. 20,000-deep ASTs refused rather than overflowing the stack. `Label` has no `Default`, so a new ingest path cannot default to `Trusted` by omission. |
| I4 | Sensitive args reject tainted unless confirmed | **Done** | `PolicyHost` resolves → evaluates → audits → acts only on `Allow`. The confirmation round trip is built. An absent rule is `Confirm`, never `Allow`. |
| I5 | Process sees only granted fds | **Partial** | Landlock confines paths; seccomp refuses `socket(2)`, UDP, and Unix sockets; `SCM_RIGHTS` passes real descriptors; `pool.rs` forks and confines once at construction so no request can be served by an unconfined process. Still open: cgroups and namespaces. |
| I6 | Audit log, append-only, before execution | **Done** | `AuditLog::record_intent` returns an `AttemptToken` with private fields, so an effect cannot be performed without a prior durable record. |

---

## Phase 0 — Foundations and baseline

- [x] Six invariants stated as testable properties (`AGENTS.md`)
- [x] Evaluation harness wired to a backend trait (`agentos-infer`)
- [x] **Threat model document** (`THREAT_MODEL.md`) — assets, boundaries, attacker capabilities, and what is explicitly not defended against
- [ ] **Baseline numbers.** Attack success rate, task success rate, tokens per task, latency per tool call, bytes written per task. **Still none measured.** This is the largest single gap in the project.
- [ ] Naive flat-token agent to compare against
- [ ] AgentDojo / InjecAgent corpus wired up

## Phase 1 — Core daemon and capability broker

- [x] Provenance types: `Val<T>`, `Label`, `Trusted<T>`, `Quarantined<T>`
- [x] `Cap<K>` with sealed marker types (compile-time handle confusion)
- [x] Tool trait with typed arguments (`Tool` in `agentos-tools`)
- [x] Append-only audit log, written before the effect (I6)
- [x] Policy rules per `(tool, argument)`, absent rule defaults to `Confirm`
- [x] Policy enforced at the tool boundary (I4)
- [x] Capability broker with real handles, lineage, attenuation, and **real revocation**: `CapRegistry::authorise`, `attenuate`, transitive `revoke`, and ids that are never reused
- [x] Escape tests: `../`, symlinks, absolute paths, and descriptor-vs-name all fail — 41 for `http.fetch`, plus the `fs.write` suite
- [x] `schemars` derives on real tool arguments (`fs.write`, `http.fetch`)
- [ ] `tokio` runtime, one session actor per task, typed mailboxes
- [ ] `cap-std` for in-process filesystem access

## Phase 2 — Process confinement

- [x] Kernel capability verified, not assumed. Landlock is compiled in and was confirmed by *building a ruleset and escaping it* — `/etc/passwd`, `/proc/self/mem`, `/sys/kernel/security`, and a symlink out all denied.
- [x] seccomp confirmed enforcing: a real BPF allowlist installed, a child refused disallowed syscalls with `ENOSYS`, and `CONFIG_SECCOMP_FILTER=y`.
- [x] `PR_SET_NO_NEW_PRIVS` in every confined child, confirmed to default to `0`.
- [x] Landlock ABI-version fallback matrix, fail closed.
- [x] `socket(2)`, UDP, and Unix sockets refused under seccomp, closing the hole Landlock leaves.
- [x] A `FORBIDDEN` table naming the syscalls that must never appear in any profile, each with its reason, checked both by `Profile::refused` and again by `apply` refusing to install a filter that has grown one.
- [x] `SCM_RIGHTS` fd passing, with `O_NOFOLLOW|O_DIRECTORY|O_NONBLOCK` on the receive side.
- [x] **Pre-forked, pre-confined worker pool.** Workers are confined at construction; a request never pays for confinement and can never be served by an unconfined process. Request caps, idle timeouts, and liveness are enforced, with the death check going through `waitpid(WNOHANG)` rather than `kill(pid, 0)` because a zombie answers `kill` like a live process.
- [x] `ptrace`, `clone`/`clone3` (refused together, or neither), `io_uring` (closed at setup), `perf_event_open`, `memfd_create`, `userfaultfd`, `bpf` are outside both Landlock and every profile.
- [ ] cgroups v2 limits. **Blocked:** root-owned, no delegation for this user. So there are no CPU, memory, or pid limits.
- [ ] User and mount namespaces via `rustix`. **Blocked:** `unshare(CLONE_NEWUSER)` fails; cause still not pinned down.

**Consequence:** the sandbox rests on Landlock + seccomp plus descriptor passing. The network hole Landlock leaves is closed, and I5 is now demonstrable rather than merely designed. What is *not* there is resource containment: a confined process can still exhaust CPU or memory, because cgroups and namespaces are unavailable on this host.

## Phase 3 — Inference layer and constrained decoding

- [x] Backend trait with roles P and Q
- [x] Constrained decoding on the Q side, with schema-driven validation host-side
- [x] **Schema design rules for Q**: enum, bounded int, bool, date; strings only with tight regex and length bounds; unbounded free text as `Quarantined<String>`. `free_text_never_appears_in_the_typed_view` is the test.
- [x] `label-leak counter` for I1, with the gate on the count being exactly zero
- [ ] Local or self-hosted engine for constrained decoding. Hosted APIs cannot run our CFG at the sampler, so the real engine is still unwired.
- [ ] Repair loop for invalid planner output
- [ ] P sees typed summaries only. The quarantine boundary exists; the *use* of it inside a plan is not built.

## Phase 4 — Plan DSL, taint tracking, policy

- [x] Parser: no `eval`, no recursion, no dynamic dispatch, bounded loops
- [x] AST with structural validation
- [x] Interpreter that moves labeled values, never raw strings
- [x] Taint propagates through field projection, len, extraction, and iteration
- [x] `report` refuses any value that can carry text
- [x] Policy engine with per-argument rules
- [x] Confirmation requests show provenance (source kinds), not a placeholder string
- [x] **Confirmation round trip.** `Trusted::confirmed` is reachable from a real build.
- [x] Adversarial review: 12 findings, all fixed and regression-tested
- [ ] Replanning: P sees typed summaries only. No inference layer wired in yet.
- [ ] AgentDojo attack success rate measured against the baseline

## Phase 5 — Typed event bus

- [x] Event schema defined, deliberately with **no** variant for raw stdout/stderr/tracepoint payloads
- [ ] `aya` eBPF programs
- [ ] In-kernel filtering by cgroup id
- [ ] `postcard`/`rkyv` encoding
- [ ] Two consumers: audit verification and compact Controller feedback
- **Blocked:** `unprivileged_bpf_disabled` was set to 0, but uid 1000 has zero effective capabilities (`CAP_BPF`, `CAP_PERFMON` absent). Loading still unverified.

## Phase 6 — Hierarchical context pager

- [ ] L1 / L2 / L3 tiers
- [ ] Deterministic prompt assembly from the task graph
- [ ] `fjall` LSM, group-commit fsync
- [ ] Crash replay
- [ ] Prompt tokens per step measured flat as task length grows

## Phase 7 — Hardening and release

- [ ] `cargo-fuzz` the DSL parser, IPC decoders, policy engine
- [ ] External-style red team: multi-step, confused-deputy
- [ ] systemd unit with hardening options
- [ ] Reproducible build, `.deb`/`.rpm`
- [x] Project conventions and build instructions (`AGENTS.md`)
- [x] "What this does not protect against" documentation (`THREAT_MODEL.md` §7)

---

## Known open risks

1. **No measurement.** Every number in the evaluation matrix is unmeasured. Claims about reduced attack success rate are currently unfounded, and this is the risk that most undermines the rest: a system that cannot show an attack failing has not shown it is blocked.
2. **No resource containment.** cgroups and namespaces are blocked on this host, so a confined process can exhaust CPU or memory. Landlock and seccomp control *reach*, not *cost*.
3. **eBPF loading unverified** after the sysctl change.
4. **The pool's confinement is Unix-only and its test image is a reference.** `agentos-worker` proves the mechanism; it is not the real interpreter. A different image may need loader syscalls the `Worker` profile does not grant, and the failure mode is a worker that cannot start rather than one that runs too freely — the safe direction, but still a deployment hazard.
5. **`Profile::Worker` grants `prctl`.** It is safe as installed — the filter is already in place and can only be made more restrictive — but `prctl` is a broad syscall to hand out and the grant exists for a startup path that has not been pinned to the specific call.
6. **The quarantine engine is a no-op.** I2 is demonstrated; the thing that will actually read documents is not built.

## Decisions taken

- **No Docker.** WSL2 alone. Docker's own seccomp profile would stack with ours and make blocked-syscall debugging ambiguous.
- **Fail closed over fail open.** An absent policy rule is `Confirm`, never `Allow`. An uninspectable value is denied, never waved through. A descriptor handed over as a name is refused.
- **Untrusted text is never stored in the audit log.** A record is a Controller input; storing attacker prose there would reopen injection one layer over.
- **Confinement happens before the engine starts, in a separate binary.** A model client that opened its socket before `landlock_restrict_self` would be holding a live socket in a process whose `socket(2)` is about to be denied.
- **Workers compile everywhere and refuse at runtime.** A Windows build that needed a cfg in every dependent manifest would push someone toward deleting the dependency instead.