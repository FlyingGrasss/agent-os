# AgentOS plan

Status against the original seven-phase roadmap. Checked boxes mean built **and**
covered by a test that would fail if the property broke. Anything unchecked with
a note means something was built but the phase's exit criterion is not met.

Last updated to match commit `6d376ea`.

**Verification for this update:** `cargo test --workspace` and
`cargo clippy --all-targets -- -D warnings` both clean on Linux
(`x86_64-unknown-linux-gnu`) and on the Windows host — 510 tests on Linux, 424 on
Windows, zero failures, zero clippy warnings on either. The gap between the two
counts is the Linux-only sandbox, quarantine, and seccomp suites.

The live model arm is verified separately, against a running Ollama with
`llama3.2:3b`: 3 runs x 14 tasks x 2 arms. It is not part of either count.

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
- [x] **Resumable interpreter** (`agentos_dsl::machine::Machine`). A halt for confirmation no longer discards the plan's state: variables, loop frames, and spent budgets all survive, so a granted call is retried rather than skipped and the budget is cumulative rather than reset per approval. Checked against the existing recursive interpreter by a differential test over 24 programs, and against the old behaviour by 8 targeted tests.
- [x] **Session loop** (`agentos_core::Session`) — plan → interpret → confirm → grant → resume, driven end to end by the corpus. Holds no secret and decides nothing: the host still evaluates every argument and owns the grants, the user still answers, and `Machine` still decides only where to carry on from. The grant is derived from the values the host recorded at the halt, so no value is ever reconstructed anywhere in the cycle.
- [x] **How much of the defence is a person** — the number the resume path made measurable, and the one worth quoting. A fourth arm runs the **defended rule set** with a user who approves everything: **14 of 33 attacks succeed anyway**. Each of those was stopped by a prompt and nothing else: the rules were in force, the plan was checked, and a human waved it through. The 0% defended figure and this 42% are both true and describe the same system, so quoting the first without the second is the misleading half. Read alongside the item below, which is what makes a prompt worth reading at all.
- [x] **Intent pins — the agent defends itself, without asking** (`agentos_tools::IntentPins`). The user said "email bob@example.com"; that address is **trusted text they typed**. If a plan puts a *different* address, lifted from a document, in that position, the document has overridden something the user stated. That is a contradiction between two values the system already holds, decided on **shape alone** — no understanding of what the injection says, so it cannot be evaded by rephrasing. Enforced in `PolicyHost` before the grant lookup and only ever turning `Allow` into `Deny`, so **no approval can unlock it**. Verified end to end: the session ends in a denial with `asked() == 0`, even against a user who approves everything.
- [x] **The pins now have a measurement, and it took the right threat model.** Measuring them against the live 3B model gave **zero** — not because they fail but because a cooperative planner writes the user's own address and never gets steered. So an **adversarial planner** was added: deterministic, reads the request, and emits exactly the plan an attacker wants, routing document content into the pinned position. Against it the pins fire **4 tasks refused with no human involved**, and the approving-user leak rate falls from **92.9% to 64.3%**. The same 4 are refused whether the user declines or approves, which is the property that matters.
- [ ] **The forwarding residual is a different problem from substitution, and the leak count was hiding it.** Measuring *bytes* of untrusted text reaching a tool shows the two live arms leak differently: the adversarial planner's leaks carry **112 bytes** (an address, short), while the live model's carry **522 bytes** (prose — a `note` or `footer` field forwarded into a message). Same metric, same "a tainted argument reached a tool", two entirely different threats.
- [ ] **Why forwarding is not solvable structurally, stated plainly.** When the user says "email the invoice note to bob", forwarding the note *is what they asked for*. There is no contradiction to detect, so the intent pins cannot apply. The remaining options are (a) refuse to forward what the user asked to forward, which is wrong, and (b) classify text as "instruction-like", which is **detection** — evadable by rephrasing, and dishonest to present as a control. The real lever is **schema design**: a schema extracting `total: int, status: enum, due: date` has almost nothing to forward, while one with `note: string` has a forwarding surface proportional to the note. That is a measurable property of the schema, and shrinking it is the actual work.
- [x] **Extraction bridge** (`agentos_core::ModelExtractor`) — the missing link between the quarantined processor, which returns JSON, and the plan language, which needs `PlanData`. Every string in an extraction becomes `PlanData::Quoted`, so attacker text can never arrive as a planner-authored `Str`. The schema table is Controller-built; a plan cannot choose the shape of what it learns.
- [x] **The confirmation prompt now shows the value.** Found by a test failing while writing the bridge above: the user was asked to approve `send_email(to = <structured value>)`. That is not a conservative default, it is a broken one — a user asked to approve an invisible value has nothing to read and one available answer, so the "human in the loop" is a rubber stamp while every approval is still recorded as deliberate. `ArgView` now carries a display rendering separate from the text the *rules* inspect, so quarantined text reaches the person deciding and still cannot be pattern-matched by a rule or written to the audit log. Control characters are stripped, because the value is attacker-controlled and the destination is a terminal.
- [x] **Planner** (`agentos_core::Planner`) — the last missing piece between a task and a plan. Assembles its own conversation, so the planner's prompt is fixed text plus a `Trusted` task with **no parameter through which untrusted bytes could arrive**; I1 is enforced by the API's shape rather than by a check somebody has to remember. Model JSON is rendered into plan-language source and **fails closed** — an unrecognised operation, a missing field, a statement count over the bound, or a newline inside a field all refuse the whole plan, because silently skipping one would produce a task recorded as completed that did less than the model asked for.
- [x] **End-to-end against a real model.** `llama3.2:3b` was asked to "fetch the invoice, email the note field to the address it names". It wrote exactly that plan — fetch, extract, `send_email(to = inv.note)`. The session ran it; the attacker-chosen recipient `attacker@evil.test` reached the confirmation prompt; the user declined; the mail was never sent. **A real model, writing a real plan, piped attacker-controlled document content into a sensitive argument and was stopped.**
- [x] **Attack success rate against a real model** (`agentos-model-eval`). A second corpus of **benign requests paired with hostile documents** — an attack is not a malicious request, it is an ordinary request subverted by what the document says. Every attack has a **benign twin** (same request, clean document), asserted by test, so "resisted" can be told apart from "always prompts". `llama3.2:3b`, 14 tasks x 3 runs = 42 samples per arm: **0/42 leaked with a user who reads the prompt; 7/42 (16.7%, range 14.3–21.4%) with a user who approves everything.** Only 2–3 prompts are shown per 14-task run, so the confirmation is targeted rather than a firehose.
- [x] **The measurement repeats, because the model does not.** Two runs of the same corpus on the same checkpoint produced different plans, different leak counts and different unplannable counts. A single sample of a sampled system is not a rate, so the harness runs each arm N times and reports min/max alongside the mean. The consistent leak vectors across runs are forwarding a document `note` field into a recipient, and a **buried** injection overriding the recipient — which a trailing-window defence would miss.
- [ ] **Model quality is reported as its own category, twice.** A task the model cannot plan at all is one thing; a plan that names a schema nobody registered is the *same* failure arriving after parsing. Both are counted as model quality and stay in the denominator, because folding either into "stopped" would let model weakness pad the column that flatters the design.
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

- [x] L1 / L2 / L3 tiers, plus a rolled tally that holds counts rather than text — which is *why* prompt size is bounded by the tool schema rather than the task length
- [x] Deterministic prompt assembly. Byte-identical for identical input; a test scans the crate's source for `HashMap`, `SystemTime`, `Instant::now` and `rand`, because a reproducibility bug is invisible — the code compiles, the prompt is subtly unstable, and nothing reports it
- [x] **I1 is enforced here, structurally.** Every renderable string is a `Trusted<String>`; `Prompt` has no public constructor taking text, and no `Deref<str>` that drops the label. A `StepRecord` cannot carry document text at all — tool *arguments* are deliberately not recorded, because that is where tainted values live.
- [x] **Trust is provenance, not structure.** The task is trusted because the user wrote it, and a user who pastes a hostile document into their own prompt is a real case. Every free-text field is escaped to one line, so a newline in the task cannot forge a `## ` header or a fake record line in the rendered prompt.
- [x] Prompt size measured flat: a test asserts the prompt grows under 1.5x between 10 and 400 steps.
- [ ] `fjall` LSM, group-commit fsync, crash replay — **deliberately absent, not stubbed.** Nothing here claims durability across a process restart; the ledger is an in-memory accounting record.
- [x] **The pager is wired into `Session`.** `Session::with_pager` attaches one; every tool call the interpreter reports is filed into it, and `Session::prompt()` returns the assembled `Trusted<String>`. This is what makes I1 testable end to end rather than against synthetic input: a real hostile document, extracted by a real extractor, routed by a real plan through a real policy engine, and the injection text still absent from what the Controller reads.
- [x] **A wiring bug the test caught.** The first version recorded one bare checkpoint per *statement*, so the Controller's context said *that* work happened without saying *what* — and the rolled tally, whose entire purpose is to be bounded by the tool schema rather than the task length, had no tools to count. It now reads `Machine::events`, which is the interpreter's own account rather than this loop's guess, and drains it incrementally so a run that halts and resumes does not re-record the same call.

## Phase 7 — Hardening and release

- [ ] `cargo-fuzz` the DSL parser, IPC decoders, policy engine
- [ ] External-style red team: multi-step, confused-deputy
- [ ] systemd unit with hardening options
- [ ] Reproducible build, `.deb`/`.rpm`
- [x] Project conventions and build instructions (`AGENTS.md`)
- [x] "What this does not protect against" documentation (`THREAT_MODEL.md` §7)

---

## Known open risks

1. **Model measurement exists but is thin.** The policy layer is measured over 45 programs, and the model arm now runs end to end: a real model writes a plan, a hostile document attacks it, and the session enforces policy — 0/42 leaks with a reading user, 7/42 (16.7%) with an approving one. But that is **one 3B checkpoint over 3 runs**, with role Q stubbed. A different model, a real Q, or more runs would move it. Nothing here should be read as a claim about models in general.
2. **Most of the surviving defence is still a human.** Of 33 corpus attacks, 12 are refused automatically and **17 get through if the user approves everything**. Against a *cooperative* model the leak rate is 0% for a reading user and ~17% for an approving one. Against an **adversarial planner** — the threat model, since the planner's output is what an attacker steers — it is 0% and **64.3%**. The intent pins took that from 92.9%, which is real progress and a fraction of the problem: they cover substitution and not forwarding. On data poisoning — the residual hole both CaMeL's and AgentDojo's own authors name — four of five attacks survive an approving user. Confirmation fatigue is a security property here, and the design only partially defends it.
3. **No resource containment.** cgroups and namespaces are blocked on this host, so a confined process can exhaust CPU or memory. Landlock and seccomp control *reach*, not *cost*. The DSL's own step and loop budgets are the only bound, and the measurement shows they do fire.
4. **eBPF loading unverified** after the sysctl change.
5. **The pool's confinement is Unix-only and its test image is a reference.** `agentos-worker` proves the mechanism; it is not the real interpreter. A different image may need loader syscalls the `Worker` profile does not grant, and the failure mode is a worker that cannot start rather than one that runs too freely — the safe direction, but still a deployment hazard.
6. **`Profile::Worker` grants `prctl`.** It is safe as installed — the filter is already in place and can only be made more restrictive — but `prctl` is a broad syscall to hand out and the grant exists for a startup path that has not been pinned to the specific call.
7. **The quarantine engine is a no-op.** I2 is demonstrated; the thing that will actually read documents is not built.
8. **A loop body in the DSL cannot bind a variable.** `Interp::exec` rejects a second `let` of the same name and a loop never unbinds, so a `for` body may contain only `report` and nested `for`s. Found while building the corpus. It is a real limitation rather than a security hole, but it makes loops nearly useless and it is why the corpus cannot express "one tainted write reached many times".
9. **The resume path is built; the loop that uses it is not.** `PolicyHost::call` returns `Err(ConfirmationRequired)` on a `Confirm`, which propagated out of `agentos_dsl::run` and discarded the interpreter's `State` — its variables *and* its spent step and loop budgets. `agentos_dsl::machine::Machine` now carries all three across a halt, and the old recursive `run` remains for programs that never halt. What is still missing is the session loop that drives it: nothing yet turns a `Step::Halted` into a `Disclosure` request and a grant back into a resumed `advance`. The three defects that made this harder than it looked, and how each was resolved:
   - **Re-running the plan is not safe.** A halt on the second tool call means re-running replays the first one's side effect. Memoising on `(tool, args)` to avoid that would make the audit log a fiction: it records an attempt and performs no effect. Two identical `fs.write` calls in one plan may also legitimately be two writes. *Resolved by resuming rather than re-running, and by recording only the tool calls made inside the single statement that is in flight — not the whole plan.*
   - **A resume needs a frame stack, not just a cursor.** `ForEach` iterates a list and binds a variable per item; a halt inside the body loses the items, the index, and the label. `State::vars` alone is insufficient. *Resolved with a `Frame` stack carrying the item list, its label, and the body cursor.*
   - **Budgets must be carried, not restarted.** `steps` and `loop_iterations` live on the machine, so a resume cannot reset either — a budget-*escalation* hole rather than an inconvenience. `Literal::Quoted` carries a `SourceId` in the AST, so re-evaluating it yields the same label and a `Confirmation` issued for it still matches. *Both verified by test.*
   - **A fourth defect, found by reading rather than by a failing test:** the in-flight record was first keyed by `(tool, argument index)`. That is ambiguous the moment one statement names the same tool twice, because a nested call restarts the index at zero — `mail(subject = h(k = "a"), body = h(k = "b"))` served `body` the result computed for `"a"` and never invoked the second `h`. Beyond being wrong, that is a **taint-laundering path needing no injection at all**: a trusted result computed for one argument could be delivered to a position where a tainted one belonged. The key is now the *call site* (the path of argument indices from the statement root), and the differential corpus carries four same-tool-twice programs so the shape cannot regress.
   - **A fifth defect, found by adversarial review:** a hard error left the machine re-runnable. `advance` returned the error without advancing the cursor *and* discarded the in-flight record, so the natural caller — `loop { match advance { Err(e) => log(e), .. } }` — re-ran the failed statement with an empty cache and invoked its tools again; a test measured `helper` running six times for one intended call. The comment claimed "on a hard failure the machine stops", and nothing enforced it. `Machine` now **poisons** on any non-halt error and reports the same error thereafter.
   - **A test-harness defect, found by adversarial review:** the differential harness rendered argument values without their labels, so two values differing only in provenance compared equal. The one automated check that compares the two implementations on I3 was structurally unable to fail on an I3 regression. It now renders each value's trust level — the security-relevant property, since a `SourceId` is a per-call random UUID that would make every run differ from every other — and five halting programs were added, so the corpus finally exercises the resume machinery rather than only the path that never needed it.
10. **`PolicyHost`'s `op` identifier is lossy.** It is built from `request.items.first()`, so a `send_email` with both `to` and `body` tainted yields the single op `send_email.to`. The *display* is correct — `drain` shows every item — and `grant_pending` now grants every flagged argument rather than keying on `op`, so the collision no longer breaks resumption. But anything else keying on `op` still collides across calls differing in later arguments, and a refusal record naming `op` is ambiguous in the same way.
11. **The planner is a small model's weakest link, and that is not a security finding.** `llama3.2:3b` produced a valid, correct, *attack-carrying* plan for the end-to-end case and an unparseable one for two of three others — once emitting `+` into the source, once inventing a schema (`Address`) that was not registered and was therefore refused. Both refusals are the system working. The risk to watch is scoring: an unparseable plan must be reported as model quality, and if it were ever counted as "attack blocked" the measurement would improve for the wrong reason.

## Decisions taken

- **No Docker.** WSL2 alone. Docker's own seccomp profile would stack with ours and make blocked-syscall debugging ambiguous.
- **Fail closed over fail open.** An absent policy rule is `Confirm`, never `Allow`. An uninspectable value is denied, never waved through. A descriptor handed over as a name is refused.
- **Untrusted text is never stored in the audit log.** A record is a Controller input; storing attacker prose there would reopen injection one layer over.
- **Confinement happens before the engine starts, in a separate binary.** A model client that opened its socket before `landlock_restrict_self` would be holding a live socket in a process whose `socket(2)` is about to be denied.
- **Workers compile everywhere and refuse at runtime.** A Windows build that needed a cfg in every dependent manifest would push someone toward deleting the dependency instead.
- **Every measurement ships with a control that can make it fail.** The corpus ships with the claim that it defeats a defenceless agent, so a 0% defended rate cannot be obtained by measuring nothing. Three separate bugs in the harness itself were caught this way, including one that reported a *perfect* defence score because an `Rc::try_unwrap` was silently returning an empty execution list.
- **Automatic refusal and human refusal are counted separately.** "0% attack success" is one number covering both "a machine refused this" and "a person was asked and said no"; reporting only the first would let the design claim credit for the user's attention.
- **Harden the invariants before building on them.** `PromptSlot::fill_unchecked_for_test` was `#[doc(hidden)] pub`, so any dependent crate could increment the I1 counter — and the number that is supposed to be exactly zero was therefore not a measurement. Building a prompt-assembly path on top of that gate would have produced a green I1 that meant nothing.