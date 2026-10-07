# AgentOS plan

Status against the original seven-phase roadmap. Checked boxes mean built **and**
covered by a test that would fail if the property broke. Anything unchecked with
a note means something was built but the phase's exit criterion is not met.

Last updated after commit `e8164cc`.

---

## Where the six invariants stand

| # | Invariant | State | Enforced where |
|---|---|---|---|
| I1 | No untrusted bytes in the Controller's prompt | **Partial** | `Trusted<T>` is a separate type; `report` refuses text; `Quarantined` hides content in `Debug`. Not yet proven end-to-end because there is no prompt assembly yet. |
| I2 | Extractor has no tools, network, or filesystem | **Not started** | `agentos-infer` is a placeholder; `Extractor` is a bare trait with no capability argument. |
| I3 | Labels propagate through all operations | **Done** | `Val::map`/`zip`/`map_with_label`, interpreter's field/len/extract/iteration. 20,000-deep ASTs refused rather than overflowing the stack. |
| I4 | Sensitive args reject tainted unless confirmed | **Done, one loop open** | `PolicyHost` resolves → evaluates → audits → acts only on `Allow`. The confirmation *round trip* is not built yet: requests are queued, nothing consumes them. |
| I5 | Process sees only granted fds | **Partial** | Landlock confines the filesystem; seccomp refuses `socket(2)`, UDP, and Unix sockets. `Cap<K>` exists with sealed marker types. **Not built:** cgroup limits, namespaces, `SCM_RIGHTS` fd passing, worker pool. |
| I6 | Audit log, append-only, before execution | **Done** | `AuditLog::record_intent` returns an `AttemptToken` with private fields, so an effect cannot be performed without a prior durable record. |

---

## Phase 0 — Foundations and baseline

- [x] Six invariants stated as testable properties (`AGENTS.md`)
- [x] Evaluation harness stub (`agentos-infer` placeholder, not wired)
- [ ] **Threat model document.** Assets, trust boundaries, attacker capabilities, and what the system explicitly does *not* defend against. This is a phase exit criterion and it is still missing.
- [ ] **Baseline numbers.** Attack success rate, task success rate, tokens per task, latency per tool call, bytes written per task. None measured.
- [ ] **Naive flat-token agent** to compare against.
- [ ] AgentDojo / InjecAgent corpus wired up.

## Phase 1 — Core daemon and capability broker

- [x] Provenance types: `Val<T>`, `Label`, `Trusted<T>`, `Quarantined<T>`
- [x] `Cap<K>` with sealed marker types (compile-time handle confusion)
- [x] Tool trait with typed arguments (`Tool` in `agentos-tools`)
- [x] Append-only audit log, written before the effect (I6)
- [x] Policy rules per `(tool, argument)`, absent rule defaults to `Confirm`
- [x] Policy enforced at the tool boundary (I4)
- [ ] `schemars` derives on real tool arguments. No concrete tool exists yet.
- [ ] `tokio` runtime, one session actor per task, typed mailboxes
- [ ] Capability broker: real handles, lineage, attenuation, revocation. `CapRegistry` is a stub whose `revoke` validates a range and does nothing.
- [ ] `cap-std` for in-process filesystem access
- [ ] Escape tests: `../`, symlinks, absolute paths must fail. **No tools exist to escape from yet.**

## Phase 2 — Process confinement

- [x] Kernel capability verified, not assumed. Landlock is compiled in, ABI 7, and was confirmed by *building a ruleset and escaping it* — `/etc/passwd`, `/proc/self/mem`, `/sys/kernel/security`, and a symlink out all denied.
- [x] seccomp confirmed enforcing (`CONFIG_SECCOMP_FILTER=y`; a real BPF allowlist installed and a child refused disallowed syscalls).
- [x] BTF present for eBPF type resolution.
- [x] Landlock wrapper in `agentos-sandbox`: `Confine`, typed grants, `Enforced` proof token. 51 escape probes observed, each with a positive control.
- [x] seccomp allowlist per tool class (`Filesystem`, `Exec`), default deny, ENOSYS on refusal so a tool fails visibly rather than dying silently.
- [x] `PR_SET_NO_NEW_PRIVS` in every confined child. Confirmed it defaults to `0`, so this is required, not optional. Both Landlock and seccomp refuse without it.
- [x] Landlock ABI-version fallback matrix, fail closed. Requires ABI V6 to confine anything.
- [x] `socket(2)` and UDP refused under seccomp, closing the hole Landlock leaves. Unix sockets also refused.
- [ ] Pre-forked, pre-confined worker pool (target: ~5 ms warm, ~30 ms cold).
- [ ] cgroups v2 limits. **Blocked:** root-owned, no delegation for this user.
- [ ] User and mount namespaces via `rustix`. **Blocked:** `unshare(CLONE_NEWUSER)` fails; cause not pinned down. The AppArmor theory is disproven — that sysctl does not exist on this kernel.
- [ ] SCM_RIGHTS fd passing.
- [ ] `ptrace`, `clone`, `io_uring`, `perf_event_open` are outside both Landlock and these profiles.

**Consequence:** the sandbox rests on Landlock + seccomp. `socket(2)` is now refused, so the network hole Landlock leaves is closed. cgroups and namespaces remain blocked, so there are no CPU, memory, or pid limits and no filesystem isolation beyond the granted tree.

## Phase 3 — Inference layer and constrained decoding

- [ ] Backend trait with roles P and Q
- [ ] `schemars` → JSON Schema → grammar
- [ ] Local or self-hosted engine for constrained decoding. Hosted APIs cannot run our CFG at the sampler.
- [ ] **Schema design rules for Q**, which are the real boundary: prefer enum, bounded int, bool, date; strings only with tight regex and length bounds; unbounded free text as `Quarantined<String>`.
- [ ] Repair loop for invalid planner output.

## Phase 4 — Plan DSL, taint tracking, policy

This is the phase carrying the security claim, and it is the furthest along.

- [x] Parser: no `eval`, no recursion, no dynamic dispatch, bounded loops
- [x] AST with structural validation
- [x] Interpreter that moves labeled values, never raw strings
- [x] Taint propagates through field projection, len, extraction, and iteration
- [x] `report` refuses any value that can carry text
- [x] Policy engine with per-argument rules
- [x] Confirmation requests show provenance (source kinds), not a placeholder string
- [x] Adversarial review: 12 findings, all fixed and regression-tested
- [ ] **Confirmation round trip.** `PolicyHost` queues a `ConfirmationRequest`; nothing consumes it, so a plan halts forever. `Trusted::confirmed` is currently unreachable from a real build.
- [ ] Replanning: P sees typed summaries only. No inference layer yet.
- [ ] AgentDojo attack success rate measured against the baseline.

## Phase 5 — Typed event bus

- [x] Event schema defined, deliberately with **no** variant for raw stdout/stderr/tracepoint payloads
- [ ] `aya` eBPF programs
- [ ] In-kernel filtering by cgroup id
- [ ] `postcard`/`rkyv` encoding
- [ ] Two consumers: audit verification and compact Controller feedback
- **Blocked:** `unprivileged_bpf_disabled` was 2, user has since set it to 0, but uid 1000 has zero effective capabilities (`CAP_BPF`, `CAP_PERFMON` absent). Loading is still unverified.

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
- [ ] "What this does not protect against" documentation

---

## Known open risks

1. **No measurement.** Every number in the evaluation matrix is unmeasured. Claims about reduced attack success rate are currently unfounded.
2. **cgroups and namespaces blocked on this host.** Phase 2 cannot be complete without root or a delegated unit.
3. **eBPF loading unverified** after the sysctl change.
4. **`Label::default()` is `Trusted`.** Correct for planner-authored values, the worst default for an untrusted one. Nothing catches a future `Label::default()` on ingest.
5. **`CapRegistry::revoke` is a stub** that returns a bool and revokes nothing. It must not ship as-is.

## Decisions taken

- **No Docker.** WSL2 alone. Docker's own seccomp profile would stack with ours and make blocked-syscall debugging ambiguous.
- **Fail closed over fail open.** An absent policy rule is `Confirm`, never `Allow`. An uninspectable value is denied, never waved through.
- **Untrusted text is never stored in the audit log.** A record is a Controller input; storing attacker prose there would reopen injection one layer over.
