# AgentOS plan

Status against the original seven-phase roadmap. Checked boxes mean built **and**
covered by a test that would fail if the property broke. Anything unchecked with
a note means something was built but the phase's exit criterion is not met.

Last updated to match commit `a5559c5` plus the `agentos-eval` measurement crate.

**Verification for this update:** `cargo test --workspace` and
`cargo clippy --all-targets -- -D warnings` both clean on Linux
(`x86_64-unknown-linux-gnu`) and on the Windows host — 427 tests on Linux, 336 on
Windows, zero failures, zero clippy warnings on either. The gap between the two
counts is the Linux-only sandbox, quarantine, and seccomp suites.

---

## Where the six invariants stand

| # | Invariant | State | Enforced where |
|---|---|---|---|
| I1 | No untrusted bytes in the Controller's prompt | **Partial** | `Trusted<T>` is a separate type, so prompt assembly accepts nothing else. `leak.rs` counts every slot fill and the gate is the count being exactly zero. Still partial: there is no end-to-end prompt assembly to run the counter over a real task. |
| I2 | Extractor has no tools, network, or filesystem | **Done** | `agentos-quarantine`: `SandboxedExtractor` forks, applies Landlock, applies seccomp, and only then starts the engine. Demonstrated against a real kernel by 18 escape tests, not argued from configuration. |
| I3 | Labels propagate through all operations | **Done** | `Val::map`/`zip`/`map_with_label`, interpreter's field/len/extract/iteration. 20,000-deep ASTs refused rather than overflowing the stack. `Label` has no `Default`, so a new ingest path cannot default to `Trusted` by omission. |
| I4 | Sensitive args reject tainted unless confirmed | **Done** | `PolicyHost` resolves → evaluates → audits → acts only on `Allow`. The confirmation round trip is built. An absent rule is `Confirm`, never `Allow`. **Measured** over a 45-program corpus: 29/33 attacks succeed without the policy, 0/33 with it, and all 12 benign programs still run. |
| I5 | Process sees only granted fds | **Partial** | Landlock confines paths; seccomp refuses `socket(2)`, UDP, and Unix sockets; `SCM_RIGHTS` passes real descriptors; `pool.rs` forks and confines once at construction so no request can be served by an unconfined process. Still open: cgroups and namespaces. |
| I6 | Audit log, append-only, before execution | **Done** | `AuditLog::record_intent` returns an `AttemptToken` with private fields, so an effect cannot be performed without a prior durable record. |

---

## Phase 0 — Foundations and baseline

- [x] Six invariants stated as testable properties (`AGENTS.md`)
- [x] Evaluation harness wired to a backend trait (`agentos-infer`)
- [x] **Threat model document** (`THREAT_MODEL.md`) — assets, boundaries, attacker capabilities, and what is explicitly not defended against
- [x] **Measurement harness** (`agentos-eval`): 45 DSL programs run through the real interpreter in three arms that differ only in the rule set, with controls that make a good-looking zero impossible to obtain by accident.
- [x] **Policy denied / would-allow counterfactual** — the §9 obligation that could be met without a model, and now met. 29/33 attacks succeed against an engine that allows everything; 0/33 against the shipped rules; all 12 benign programs still run. The 0% is structural rather than surprising (fail-closed means a tainted argument can only reach Deny or Confirm), so the counterfactual control is what proves the corpus is genuinely adversarial rather than harmless.
- [x] **Automatic-versus-human split**, which is the number worth having. 12 attacks refused outright with no human involved, **17 held only by a prompt**, 4 stopped by the interpreter's step budget. Every command- and path-injection attack is in the first group; **four of five data-poisoning attacks are in the second**. That is §7.2 quantified, and it is the strongest argument in the repository that confirmation fatigue is a security problem rather than a UX annoyance.
- [ ] **Attack success rate against a real model.** **Still the largest single gap.** There is no agent loop and no model backend, so there is no task to attack; every number about model behaviour remains unmeasured.
- [ ] Task success rate, tokens per task, latency per tool call — unmeasurable until there is a task loop
- [ ] Naive flat-token agent to compare against
- [ ] AgentDojo / InjecAgent corpus wired up

## Phase 1 — Core daemon and capability broker

- [x] Provenance types: `Val<T>`, `Label`, `Trusted<T>`, `Quarantined<T>`
- [x] `Cap<K>` with sealed marker types (compile-time handle confusion)
- [x] Tool trait with typed arguments (`Tool` in `agentos-tools`)
- [x] Append-only audit log, written before the effect (I6)
- [x] Policy rules per `(tool, argument)`, absent rule defaults to `Confirm`
- [x] Policy enforced at the tool boundary (I4)
- [x] **Promotion requires a policy halt.** `Disclosure::approve` used to take any `Val` and any `&self`, so any caller holding a tainted value could mint a `Trusted` with no host, no engine, no audit entry, and no user in the loop. Harmless while nothing consumed a promoted value; a live hole the moment a resumed plan runs a tool with one. The authority to promote now lives in `Disclosure`, which is the only component that has seen both a halt and a human decision.
- [x] Confirmation requests are counted by the I1 report rather than being structurally zero
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

1. **No model-shaped measurement.** The policy layer is now measured — 29/33 attacks succeed undefended, 0/33 defended, with the corpus verified adversarial by a control. But every number about *model behaviour* is still unmeasured, because there is no agent loop and no model backend. A system that cannot show an attack failing has not shown it is blocked, and this still applies to anything involving the model itself.
2. **Most of the surviving defence is a human.** Of 33 attacks, 12 are refused automatically and **17 get through if the user approves everything**. On data poisoning — the residual hole both CaMeL's and AgentDojo's own authors name — four of five attacks survive an approving user. This makes confirmation fatigue a security property, not a usability one, and nothing in the design currently defends it.
3. **No resource containment.** cgroups and namespaces are blocked on this host, so a confined process can exhaust CPU or memory. Landlock and seccomp control *reach*, not *cost*. The DSL's own step and loop budgets are the only bound, and the measurement shows they do fire.
4. **eBPF loading unverified** after the sysctl change.
5. **The pool's confinement is Unix-only and its test image is a reference.** `agentos-worker` proves the mechanism; it is not the real interpreter. A different image may need loader syscalls the `Worker` profile does not grant, and the failure mode is a worker that cannot start rather than one that runs too freely — the safe direction, but still a deployment hazard.
6. **`Profile::Worker` grants `prctl`.** It is safe as installed — the filter is already in place and can only be made more restrictive — but `prctl` is a broad syscall to hand out and the grant exists for a startup path that has not been pinned to the specific call.
7. **The quarantine engine is a no-op.** I2 is demonstrated; the thing that will actually read documents is not built.
8. **A loop body in the DSL cannot bind a variable.** `Interp::exec` rejects a second `let` of the same name and a loop never unbinds, so a `for` body may contain only `report` and nested `for`s. Found while building the corpus. It is a real limitation rather than a security hole, but it makes loops nearly useless and it is why the corpus cannot express "one tainted write reached many times".
9. **There is no resume path for a confirmed plan, and building one is the critical path to everything left.** `PolicyHost::call` returns `Err(ConfirmationRequired)` on a `Confirm`, which propagates out of `agentos_dsl::run` and discards the interpreter's `State` — its variables *and* its spent step and loop budgets. `Disclosure` can mint a `Trusted`, but nothing can put it back. Three defects make this harder than it looks, and all three are recorded because each is a way a resume could silently be wrong:
   - **Re-running the plan is not safe.** A halt on the second tool call means re-running replays the first one's side effect. Memoising on `(tool, args)` to avoid that would make the audit log a fiction: it records an attempt and performs no effect. Two identical `fs.write` calls in one plan may also legitimately be two writes.
   - **A resume needs a frame stack, not just a cursor.** `ForEach` iterates a list and binds a variable per item; a halt inside the body loses the items, the index, and the label. `State::vars` alone is insufficient.
   - **Budgets must be carried, not restarted.** `steps` and `loop_iterations` live in `State`, so a resume that builds a fresh `State` silently resets both — a budget-*escalation* hole rather than an inconvenience. `Literal::Quoted` carries a random `SourceId`, so re-evaluating it across a resume would produce a different label and fail `Trusted::confirmed`'s label check.
10. **`PolicyHost`'s `op` identifier is lossy.** It is built from `request.items.first()`, so a `send_email` with both `to` and `body` tainted yields the single op `send_email.to`. The *display* is correct — `drain` shows every item — but anything keying an approval on `op` collides across calls differing in later arguments. Approvals must key on the full request or a digest of it.

## Decisions taken

- **No Docker.** WSL2 alone. Docker's own seccomp profile would stack with ours and make blocked-syscall debugging ambiguous.
- **Fail closed over fail open.** An absent policy rule is `Confirm`, never `Allow`. An uninspectable value is denied, never waved through. A descriptor handed over as a name is refused.
- **Untrusted text is never stored in the audit log.** A record is a Controller input; storing attacker prose there would reopen injection one layer over.
- **Confinement happens before the engine starts, in a separate binary.** A model client that opened its socket before `landlock_restrict_self` would be holding a live socket in a process whose `socket(2)` is about to be denied.
- **Workers compile everywhere and refuse at runtime.** A Windows build that needed a cfg in every dependent manifest would push someone toward deleting the dependency instead.
- **Every measurement ships with a control that can make it fail.** The corpus ships with the claim that it defeats a defenceless agent, so a 0% defended rate cannot be obtained by measuring nothing. Three separate bugs in the harness itself were caught this way, including one that reported a *perfect* defence score because an `Rc::try_unwrap` was silently returning an empty execution list.
- **Automatic refusal and human refusal are counted separately.** "0% attack success" is one number covering both "a machine refused this" and "a person was asked and said no"; reporting only the first would let the design claim credit for the user's attention.
- **Harden the invariants before building on them.** `PromptSlot::fill_unchecked_for_test` was `#[doc(hidden)] pub`, so any dependent crate could increment the I1 counter — and the number that is supposed to be exactly zero was therefore not a measurement. Building a prompt-assembly path on top of that gate would have produced a green I1 that meant nothing.