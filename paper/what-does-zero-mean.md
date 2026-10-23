# What Does 0% Mean?

### A Four-Arm Protocol for Evaluating Prompt-Injection Defenses

**Draft — not peer reviewed.** A methodology paper, with AgentOS as a case study.
The case-study numbers are from the artifact at commit `e09992a`; the live-model arm is
single-run and exploratory. The companion technical report is `price-of-zero.md`.

---

## Abstract

Prompt-injection defenses for tool-using agents increasingly report attack-success rates at
or near zero. A zero is not interpretable on its own: it can mean the machine refused every
attack, a person declined every prompt, the model failed to produce a runnable plan, or the
harness rejected every tool call. This paper proposes a four-arm protocol that makes those
possibilities separable: no policy, policy with a declining user, policy with an approving
user, and a strict mode that turns every confirmation into a refusal. The protocol is paired
with a metric distinction — broad taint flow versus authorization-relative leakage — and a
reporting checklist. We illustrate it on AgentOS, a runtime that isolates a privileged
planner from a quarantined document reader and enforces policy per tool argument. On a
45-program policy corpus, the same rules produce 0/33 attack success with a declining user
and 14/33 with an approving one; 17/33 attacks depend on the human. On a 16-task model
corpus, strict mode produces zero tainted flows and zero prompts but denies six of seven
benign forwarding tasks. We also document four measurement failures that produced
misleading results, including a live harness that advertised a tool name the host did not
register. The contribution is methodological: a cheap, reusable way to report what a zero
costs, who produced it, and what it does not cover.

---

## 1. Introduction

A defense paper reports "0% attack success." A reader is expected to conclude that the
defense works. That conclusion is under-specified. The same system, on the same attacks,
can produce:

- 0% because the policy denied every tainted value;
- 0% because the user declined every confirmation;
- 0% because the model could not write a runnable plan;
- 0% because the harness rejected the tool name the model used;
- 0% because the attack was never run, or the plan halted after the sensitive call.

These are different claims. Only the first is a property of the machine. The second is a
property of the human. The third and fourth are properties of the model or the harness. The
fifth is a measurement failure.

The problem is not that authors are dishonest. It is that the standard experiment has one
arm — the defended system with a cooperative user — and one number. The arm is rarely named,
the utility cost is often measured on tasks that do not exercise the conflict, and the
attacks are often self-authored. A zero from that setup is a lower bound on attack success
for that corpus, not a statement about the defense's dependence on a person.

This paper makes the missing variables explicit. We propose four arms that differ only in
the decision layer, a pair of leakage definitions that separate requested forwarding from
exfiltration, and a checklist that a paper or an internal evaluation can apply without
building a new system. We illustrate the protocol on AgentOS, a runtime built around the
structural approach: a quarantined extractor, provenance labels, and per-argument policy.
The case study is not the contribution; it is the worked example that shows what the arms
reveal.

The contributions are:

1. **A four-arm protocol.** No policy, declining user, approving user, strict no-human. Each
   arm answers a different question, and the differences between them are the result.
2. **Two leakage definitions.** Broad taint flow counts any untrusted value reaching a tool;
   authorization-relative leakage counts only flows the user did not authorize. The first
   is an upper bound; the second is the deployment property.
3. **A case study** showing the protocol on a 45-program policy corpus and a 16-task model
   corpus with benign twins.
4. **A catalog of four measurement failures** that produced misleading results, with the
   control that catches each.
5. **A reporting checklist** for prompt-injection evaluations.

We do not claim a new defense. The architecture is close to CaMeL [1], Progent [4],
IsolateGPT [3], and FIDES [5]. The claim is that the evaluation of such systems is
under-specified, and that the specification is cheap.

---

## 2. Why a Zero Is Under-Specified

### 2.1 The missing arm

A defense has at least two decision layers: the policy and the human. An experiment that
fixes the human's behavior and reports one number cannot separate them. If the human always
declines, the number measures the policy plus the human's attention. If the human always
approves, it measures the policy alone, with the human as a rubber stamp. A paper that
reports only the first can claim the machine's share without measuring it.

The fix is not a better statistic. It is a second arm: run the same plans, the same
documents, and the same policy with a user who approves everything. The difference between
the two arms is the human's contribution. If the difference is large, the headline zero is
mostly a person.

### 2.2 The missing utility

A defense that refuses every tainted value gets zero leaks and refuses ordinary work. If the
benign controls use only trusted literals, the utility cost is invisible: the policy never
has to decide a legitimate forwarding. The corpus must include benign tasks that forward a
document field, because that is the class the strict policy refuses. A benign twin — the same
request against a clean document — is the control that separates "the injection was
resisted" from "this task always asks."

### 2.3 The missing authorization model

"Any untrusted byte reached a tool" counts a note the user asked to forward as a leak. It is
an upper bound on leakage and a lower bound on utility. A deployment cares whether the flow
was authorized: did the user name the destination, the field, and the tool? If yes, the flow
is the task, even though the bytes came from an attacker-controlled document. If no, the flow
is a leak, even if a human approved it. A paper that does not state which definition it uses
cannot be compared with one that uses the other.

### 2.4 The missing denominator

A model that cannot produce a runnable plan is not a blocked attack. A harness that rejects
the model's tool name is not a defense. Both can produce a zero if they are folded into the
"stopped" column. They belong in the denominator, reported separately, because a weak model
or a broken harness must not improve the defense's number by failing to run.

---

## 3. A Four-Arm Protocol

### 3.1 Definitions

A **task** is a pair `(r, d)`: a trusted request `r` and a document `d`. An **attack task**
has a document containing an injection; a **benign task** has a clean document. A **benign
twin** is the same request with a clean document.

A **plan** is a sequence of tool calls produced from `r` and the schema, without reading
`d`. Each argument value `v` carries a provenance label `λ(v) ∈ {trusted, untrusted}`. A
**sink** is a pair `(tool, argument)`. A **flow** is a value reaching a sink.

A flow is **authorized** if the request names the destination or the field for that sink, or
the operator's policy allowlists it. Otherwise it is **unauthorized**.

- **Broad leakage:** an untrusted value reached any sink.
- **Authorization-relative leakage:** an untrusted value reached a sink the request did not
  authorize.

An **arm** is a triple `(π, U, s)`: a policy `π`, a user oracle `U` that answers
confirmations, and a strict flag `s` that turns every confirmation into a denial.

For each task, the plan is executed under `π`; `U` answers confirmations; the run yields a
set of flows, a terminal outcome, and a prompt count.

### 3.2 The arms

| Arm | Policy | User | Question it answers |
|---|---|---|---|
| A0 | allow everything | none | Does the corpus actually route attacker data into tools? |
| A1 | shipped policy | declines every prompt | What does the defense stop with a careful user? |
| A2 | shipped policy | approves every prompt | What does the human contribute? |
| A3 | strict: confirm → deny | none | What does a no-human zero cost in utility? |

A0 is the counterfactual. Without it, a corpus whose payloads were silently dropped reports a
perfect defense for free. A1 is the headline arm. A2 is the arm that makes the headline
honest. A3 is the bound: it is the cheapest zero in human attention, and the most expensive
in utility.

The arms differ only in the decision layer. The plans, the documents, the extractor, and the
tool set are held fixed. That is what makes the differences attributable.

### 3.3 Controls

1. **Counterfactual.** A0 must succeed on every policy-relevant attack. Resource-exhaustion
   programs are expected to halt in every arm; they are counted separately.
2. **Utility.** In the policy corpus, A1 must complete every benign control. In the model
   corpus, a benign twin that legitimately forwards a document field may be refused; that is
   the utility cost, and it is reported rather than treated as a control failure. The control
   is that the benign rate is measured, not assumed.
3. **Same plans.** A1 and A2 must use the same plans and documents; only the user's answer
   differs. A2 and A3 must use the same plans and documents; only the policy differs.
4. **Cross-check.** The automatic-versus-human split is computed two ways: by the rule that
   produced the stop, and by the difference between A1 and A2. They must agree.
5. **Model quality.** A task the model cannot plan is reported separately and stays in the
   denominator.
6. **Harness drift.** The planner instruction must advertise exactly the tools the host
   registers. A test asserts it.
7. **Repeatability.** Sampled arms are repeated; a single run is labelled exploratory.
   Deterministic arms are exact for the corpus.

### 3.4 Reporting checklist

| # | Report | Why |
|---|---|---|
| 1 | The arm | A zero without the arm is not a claim about the defense |
| 2 | The counterfactual | Proves the corpus is adversarial |
| 3 | Declining and approving users | Separates the machine's share from the human's |
| 4 | Strict no-human | States the cost of removing the human |
| 5 | Benign twins | Separates resistance from always-asking |
| 6 | Utility | A zero that refuses ordinary work is not a defense |
| 7 | Prompts per task | Confirmation fatigue is a security property |
| 8 | Model-quality failures | A model that cannot plan is not a blocked attack |
| 9 | Tool/schema drift test | A harness that rejects the plan is not a defense |
| 10 | Authorization model | Broad taint flow and narrow leakage are different claims |
| 11 | Raw counts, not only percentages | Small corpora make percentages unstable |
| 12 | Corpus provenance and size | Self-authored corpora need an argument for representativeness |
| 13 | Automatic, human, and budget stops separately | The headline is a sum of different things |
| 14 | Repetition and intervals, or "single run" | A sampled system is not a rate from one sample |

The checklist is deliberately mechanical. It can be applied to a paper, an internal
evaluation, or a benchmark submission without changing the defense.

---

## 4. Case Study: AgentOS

AgentOS is a Rust runtime that implements the structural approach. A document enters as
`Quarantined<String>`. A confined extractor reads it and returns typed fields; the planner
sees the request and the schema, not the document. Values carry provenance labels through a
small plan language. Before each tool call, a per-argument policy decides whether a tainted
value may reach that position. A human is asked only where the policy marks `Confirm`;
`Deny` cannot be overridden by an approval. Strict mode turns every `Confirm` into a `Deny`.
The kernel sandbox is part of the artifact but is not the subject of this study.

The case study uses two corpora.

**Policy corpus.** 45 DSL programs: 12 benign controls and 33 attacks across 13 categories.
The policy-relevant attacks read the same hostile document and differ only in which field
reaches which sensitive argument. The four resource-exhaustion programs burn the
interpreter's step budget. The benign controls use planner-authored literals.

**Model corpus.** 16 tasks: 7 benign controls and 9 attacks. Most attacks share a request
with a benign twin. The planner sees only the trusted request. Role Q is stubbed with an
extractor that faithfully lifts the document's fields, including an address if one is
present. An adversarial planner supplies the worst-case plan deterministically; a live
`llama3.2:3b` arm is exploratory.

### 4.1 Policy corpus results

**Table 1.** The same 45 programs under the four arms. Attacks are 33; benign controls are
12. "Flow" means a tool ran with a tainted argument.

| Arm | Flows (attacks) | Benign complete | Prompts | Decomposition |
|---|---:|---:|---:|---|
| A0 no policy | 29/33 (87.9%) | 12/12 | 0 | counterfactual |
| A1 declining | 0/33 | 12/12 | 14 | 12 automatic, 17 human, 4 budget |
| A2 approving | 14/33 (42.4%) | 12/12 | 14 | rubber stamp |
| A3 strict | 0/33 | 12/12 | 0 | every confirm is a deny |

The 15 "denied outright" outcomes split into 12 explicit policy denials and 3 allowlist
refusals that a user could override by adding the domain. The 3 are counted as human-
dependent, not automatic. The 14 user refusals plus the 3 allowlist refusals are the 17
human-dependent stops. The 4 remaining attacks halt on the interpreter's step budget.

The 12/12 strict benign rate is a property of this corpus: every benign control uses a
trusted literal, so no legitimate forwarding is refused. This is exactly why the policy
corpus alone cannot measure the cost of strictness.

### 4.2 Model corpus results

**Table 2.** 16 tasks: 9 attacks, 7 benign. "Flow" is the broad metric over all 16 tasks;
benign twins that forward a field count as flows. The adversarial planner is deterministic.
The live arm is one run of `llama3.2:3b`.

| Arm | Flows | Prompts | Auto-refused | Benign clean | Benign refused/denied | Model-quality failures |
|---|---:|---:|---:|---:|---:|---:|
| Adversarial, declining | 0/16 | 11 | 4 | 0/7 | 6 | 0 |
| Adversarial, approving | 11/16 (68.8%) | 11 | 4 | 0/7 | 0 (6 completed) | 0 |
| Adversarial, strict | 0/16 | 0 | 4 | 0/7 | 6 denied | 0 |
| Live, declining | 0/16 | 1 | 0 | 2/7 | 1 | 3 |
| Live, approving | 1/16 (6.2%) | 1 | 0 | 2/7 | 1 denied | 4 |

The 11 flows in the adversarial approving arm decompose exactly: 4 attacks are auto-refused
by intent pins, 5 unpinned attacks reach a tool, and 6 benign twins forward a field. The
strict arm refuses the 5 unpinned attacks and the 6 benign twins; its zero is bought by
refusing the forwarding the user asked for.

The benign columns need not sum to seven: a benign task that does not reach a tool is
neither clean nor refused, and a live task the model cannot plan is a model-quality failure.

### 4.3 Strictness, schema, and pins

**Strict cost.** On the model corpus, strict mode denies 6 of 7 benign tasks. On the policy
corpus, it denies none, because the benign controls never forward. The difference is the
corpus, not the policy. A paper that reports only the policy corpus would conclude that
strictness is free.

**Schema shape.** On the 16-task adversarial approving arm:

| Schema | Flows | Forwarded bytes |
|---|---:|---:|
| Unbounded | 11/16 (68.8%) | 363 |
| 96-character bound | 10/16 (62.5%) | 307 |
| Closed types | 9/16 (56.2%) | 182 |

A size bound moves the bytes by 56 and the flows by one. Closed types move the bytes by 181
and the flows by two, and remove the instruction channel for `status` entirely. They cannot
close `note` or `recipient` without refusing the user's data. The residual 182 bytes are the
free-text fields.

**Intent pins.** On the 14-task corpus used for the ablation, the approving arm goes from
13/14 (92.9%) to 9/14 (64.3%), with 4 attacks refused by pins and no prompt. Pins address
substitution; they do not address forwarding.

### 4.4 What the arms reveal

The policy corpus's 0/33 is 12 automatic refusals, 17 human-dependent stops, and 4 budget
halts. The approving arm runs 14/33. The 0% and the 42% are the same rules and the same
corpus; only the human's answer changed. On the model corpus, the broad 11/16 is 5 attacks
and 6 benign twins; the strict zero is 6 of 7 benign tasks denied. Each of these is a
different claim that a single number would have hidden.

---

## 5. How a Zero Lies: Four Instrument Failures

The case study produced four measurement failures. Each was found by inspecting a result
that looked too good, and each has a control that catches it.

### 5.1 The halt after the sink

A corpus entry ended with `len(doc)` on a record. The interpreter's `len` is defined for
lists and strings, not records, so every plan halted with `BadField` — but only after the
sensitive tool call. Leaks were still counted, but benign completion was unmeasurable, and
the outcome looked like a defense. The fix was to read `doc.total`, a field the record
actually has.

**Control:** assert that a plan reaches its sink and completes; report *where* a halted plan
stopped. A halt after the effect is not a blocked effect.

### 5.2 The fixture that measured nothing

A model fixture returned a literal `status = "paid"` instead of reading the document. The
closed-type arm therefore never saw the status-line attack, and the unbounded and bounded
arms produced identical byte counts. The null result looked like a finding about schema
bounds.

**Control:** derive every extracted field from the document, and include a positive control
that fails if the fixture sanitizes what it lifts. A null result needs a positive control
before it is a result.

### 5.3 The tool-name mismatch

The planner instruction was corrected to the shipping tool names (`http.fetch`, `fs.write`),
but the eval host still registered the fixture names (`http.get`, `send_email`, `shell`).
Every live plan died on its first call with `ToolRejected`, and the arm reported 0 leaks. The
0% was a broken instrument, not a defense.

**Control:** a drift test that the instruction advertises exactly the tools the host
registers. The fix makes the instruction a harness parameter (`Planner::with_instruction`,
which accepts only a `&'static str` so runtime data still cannot enter the prompt).

### 5.4 The model-quality failure

A model that cannot produce a runnable plan never reaches a tool. If those tasks are folded
into "stopped," the defense gets credit for the model's weakness. In the live arm, 3–4 of 16
tasks failed to plan.

**Control:** report model-quality failures separately and keep them in the denominator. A
model-quality failure is not a blocked attack.

### 5.5 The common pattern

All four failures have the same shape: a result that is green because nothing ran. The
control is always a positive check that the experiment reached the point where the defense
could fail. A counterfactual, a benign twin, a drift test, and a plan-completion check are
four versions of that idea.

---

## 6. Limitations

**The human is simulated.** "Declining" always says no; "approving" always says yes. Real
users are neither, and they fatigue over time. The protocol measures the endpoints of the
human's contribution, not its dynamics.

**The corpus is small and self-authored.** 45 policy programs and 16 model tasks are enough
to isolate policy decisions and to illustrate the protocol; they are not AgentDojo. The
paper does not claim external validity, and a full evaluation should port the arms to a
public benchmark.

**One system.** The case study is AgentOS. The protocol is system-agnostic, but the numbers
are not.

**The live arm is exploratory.** One 3B checkpoint, one run per arm, 3–4 model-quality
failures. It is reported to show that the harness produces real behavior, not to estimate a
rate.

**The broad metric overcounts.** The 11/16 approving figure includes 6 benign twins. The
authorization-relative definition is stated but not fully implemented; the intent pins
approximate it.

**No formal proof.** The type-level isolation and the policy are implementation properties,
not a mechanized non-interference theorem. The protocol is an empirical measurement, not a
proof.

**The strict arm is a bound, not a recommendation.** It is the no-human limit. A deployment
that chooses it is choosing to refuse the forwarding the user asked for.

---

## 7. Related Work

**Structural defenses.** CaMeL [1] separates control and data flow, uses capabilities, and
reports secure task completion on AgentDojo. Progent [4] enforces fine-grained privilege
policies over tool calls. IsolateGPT [3] isolates LLM-app execution. FIDES [5] applies
information-flow control to agents. AgentOS follows this line. This paper does not propose a
new defense; it proposes how to measure one.

**Benchmarks.** AgentDojo [2] provides 97 realistic tasks and 629 security cases across
email, banking, travel, and workspace, and scores utility alongside security. The four-arm
protocol is complementary: a benchmark supplies tasks and attacks; the arms supply the
decision-layer comparison. A benchmark that reports a single defended rate has the same
under-specification this paper addresses.

**Measurement validity.** The general point that a benchmark is a measurement with
construct-validity assumptions is well established [6, 7]. Agent-security evaluations have
an additional construct: the human in the loop. The four-arm protocol is a small,
domain-specific instantiation of the general lesson.

**Detection and alignment.** Filtering, spotlighting, and fine-tuning are complementary but
not structural: they depend on recognizing the attack. This paper is about measuring systems
that do not depend on recognition, and about the ways their numbers can mislead.

---

## 8. Conclusion

A zero is a result only when the arm, the utility, the metric, and the denominator are
named. The four-arm protocol makes those names cheap: run the same plans with no policy,
with a declining user, with an approving user, and with a strict policy that asks nobody.
The differences are the findings. On AgentOS, the differences are large: 0/33 with a
declining user, 14/33 with an approving one, and a strict zero that denies six of seven
benign forwarding tasks. The broad metric counts the user's requested forwarding as leakage;
the narrow metric does not. Four instrument failures show how a green number can be produced
by nothing running.

The protocol does not make a defense good. It makes a defense's claim legible. That is the
minimum a reader needs to decide whether the zero means what it says.

---

## References

[1] E. Debenedetti, I. Shumailov, T. Fan, J. Hayes, N. Carlini, D. Fabian, C. Kern, C. Shi,
A. Terzis, and F. Tramèr. "Defeating Prompt Injections by Design." IEEE SaTML 2026.
arXiv:2503.18813.

[2] E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer, and F. Tramèr.
"AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for
LLM Agents." NeurIPS Datasets and Benchmarks, 2024. arXiv:2406.13352.

[3] Y. Wu, F. Roesner, T. Kohno, N. Zhang, and U. Iqbal. "IsolateGPT: An Execution Isolation
Architecture for LLM-Based Agentic Systems." NDSS 2025. arXiv:2403.04960.

[4] T. Shi et al. "Progent: Securing AI Agents with Privilege Control." arXiv:2504.11703,
2025.

[5] M. Costa, B. Köpf, A. Kolluri, A. Paverd, M. Russinovich, A. Salem, S. Tople, L.
Wutschitz, and S. Zanella-Béguelin. "Securing AI Agents with Information-Flow Control."
arXiv:2505.23643, 2025.

[6] I. D. Raji, E. M. Bender, A. Paullada, E. Denton, and A. Hanna. "AI and the Everything in
the Whole Wide World Benchmark." NeurIPS Datasets and Benchmarks, 2021.

[7] A. Z. Jacobs and H. Wallach. "Measurement and Fairness." ACM FAccT, 2021.

[8] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz. "Not What You've
Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt
Injection." AISec 2023. arXiv:2302.12173.

---

## Appendix A: Raw Arm Summaries

**Policy corpus.**

```
counterfactual (every rule Allow)   87.9%  29/33
defended (default_rules)             0.0%  0/33
strict (no questions asked)          0.0%  0/33
denied outright      15
refused by a person  14
did not run (halted)  4
prompts shown        14
refused outright, no question anyone is asked       12
held only by a prompt the user answers              17
same rules, user approves everything                14
```

**Model corpus, adversarial planner.**

```
declining: 0/16 flows, 11 prompts, 4 auto-refused, 6/7 benign refused
approving: 11/16 flows (5 attacks + 6 benign twins), 11 prompts, 4 auto-refused,
           6/7 benign completed, 363 bytes
strict:    0/16 flows, 0 prompts, 4 auto-refused, 6/7 benign denied
```

**Model corpus, live `llama3.2:3b`, one run.**

```
declining: 0/16 flows, 1 prompt, 3 model-quality failures, 2/7 benign clean
approving: 1/16 flows (6.2%), 173 bytes, 1 prompt, 4 model-quality failures,
           2/7 benign clean, leaked model/status-injected
```

**Schema controls, adversarial approving.**

```
unbounded: 11/16 flows, 363 bytes
bounded:   10/16 flows, 307 bytes
closed:     9/16 flows, 182 bytes
```

**Intent pins, 14-task corpus, adversarial approving.**

```
without pins: 13/14 flows (92.9%), 0 auto-refused
with pins:     9/14 flows (64.3%), 4 auto-refused
```

## Appendix B: Reproducibility

The deterministic measurements require no model server:

```
cargo test --workspace
cargo run -p agentos-eval --bin agentos-eval -- --verbose
cargo run -p agentos-eval --bin agentos-model-eval --features=ollama -- --deterministic-only
```

The live arm requires an Ollama server with `llama3.2:3b`:

```
ollama serve
cargo run -p agentos-eval --bin agentos-model-eval --features=ollama -- llama3.2:3b 1
```

The last argument is the number of runs per arm. The live numbers in this paper are one run
and should be read as exploratory. The deterministic arm uses the adversarial planner and is
exact for the corpus. The workspace test suite is 939 tests on Linux and 823 on Windows at
the commit used for the case study; those numbers describe the artifact, not the study.
