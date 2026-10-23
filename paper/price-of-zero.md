# The Price of Zero

### Measuring the Utility and Human Cost of Prompt-Injection Defenses

**Draft — not peer reviewed.** This is the case-study technical report. The methodology
paper is `what-does-zero-mean.md`. It is derived from the AgentOS artifact at commit
`e09992a`. The deterministic results are reproducible from the repository. The live-model
results are single-run and are marked exploratory throughout. Numbers are descriptive, not
statistical estimates.

---

## Abstract

Prompt-injection defenses for tool-using agents increasingly report attack-success rates at
or near zero. Those numbers are usually reported without saying what, or who, was in the
loop. We present a measurement study of AgentOS, a runtime that separates a privileged
planner from a quarantined document reader, tracks provenance through a plan language, and
enforces policy per tool argument. We run the same corpora under four arms: no policy,
policy with a user who declines every prompt, policy with a user who approves every prompt,
and a strict mode that turns every confirmation into a refusal. On a 45-program policy
corpus, the no-policy arm succeeds on 29/33 attacks. The shipped policy with a declining
user reports 0/33, but 17/33 attacks depend on the human: with an approving user, 14/33
succeed. On a 16-task model corpus, strict mode reports zero tainted flows and zero prompts,
but denies six of seven benign forwarding tasks. A 96-character schema bound reduces
forwarded bytes from 363 to 307; closed types reduce them to 182. Intent pins cut the
approving-arm substitution rate from 13/14 to 9/14, but do nothing for forwarding. We argue
that a zero without its arm is not a property of a defense, propose authorization-relative
leakage as the metric that separates requested forwarding from exfiltration, and document
three measurement failures that each made a reported result meaningless before being found.

---

## 1. Introduction

An agent that reads a web page, an email, or an invoice and then calls tools is exposed to
indirect prompt injection: the document can contain text that the model treats as an
instruction. A large body of work responds with detection, filtering, or alignment. A
smaller body responds structurally: the model that decides what to do is not allowed to
read attacker-controlled text, and the values that flow into tools carry provenance that a
policy can inspect.

AgentOS is an implementation of the structural approach. A quarantined extractor reads the
document and returns typed fields. The planner sees the user's request and the schema, not
the document. Every extracted value carries a label. Before a tool runs, a per-argument
policy decides whether a tainted value may reach that position. A human is asked only where
the policy says a legitimate flow may exist. A strict configuration removes the human by
turning every confirmation into a refusal.

The architecture is close to CaMeL [1], Progent [4], IsolateGPT [3], and FIDES [5]. We do
not claim a new architecture. We claim a measurement: the cost of the zero is usually
missing from the report, and the missing cost changes what the zero means.

Three observations motivate the study.

First, a declining user and an approving user are different systems. The same rules produce
0/33 and 14/33 on the same corpus. Reporting only the first is not a conservative choice; it
attributes the user's attention to the machine.

Second, strict zero is achievable but not free. If every tainted value is refused, no
attacker-controlled value reaches a tool. The same rule refuses the note the user asked to
forward. On a model corpus with benign twins, strict mode denies six of seven benign tasks
while stopping every attack. A policy corpus built only from trusted-literal benign controls
cannot see this cost, because it never asks the system to forward anything.

Third, the metric matters. "Any untrusted byte reached a tool" counts a requested
forwarding as a leak. It is an upper bound on leakage and a lower bound on utility. A
narrower metric — an untrusted value reached a slot the user did not authorize — is what a
deployment actually cares about, and it is what the benign twins are for. We define both and
report the broad one, because that is what the artifact measures, while making the
distinction explicit.

Our contributions are:

1. A four-arm measurement protocol that separates automatic refusal, human refusal, human
   approval, and strict no-human operation.
2. Measurements on a 45-program policy corpus and a 16-task model corpus, including benign
   twins, an adversarial planner, schema controls, and intent pins.
3. A precise decomposition of where the zero comes from: 12 automatic refusals, 17
   human-dependent stops, and 4 budget halts on the policy corpus; 4 intent-pin refusals,
   5 unpinned attacks, and 6 benign forwarding flows on the model corpus.
4. A methodological finding: three separate instrument failures each made a reported result
   meaningless, including a live-model harness that advertised a tool name the host did not
   register.
5. The argument that 0% must be reported with its arm, its utility cost, and its
   authorization model.

---

## 2. Threat Model and Scope

### 2.1 Attacker

The attacker controls a document the agent reads: a web page, an email body, an invoice, or
a tool result. The attacker does not control the user's request, the model weights, the
runtime, the policy table, or the audit log. The attacker's goal is to cause a tool effect
the user did not authorize: send data to an attacker-chosen recipient, write to an
attacker-chosen path, execute an attacker-chosen command, or corrupt a value the user will
act on.

The model may be cooperative or adversarial. A cooperative model writes the plan the user
asked for. An adversarial model writes the plan the attacker wants. The defense must hold in
both cases, because the planner's output is the attack surface, not its intentions.

### 2.2 In scope

- Instruction injection: attacker prose that attempts to redirect the plan.
- Value substitution: the document supplies a recipient, URL, path, command, or amount that
  replaces a value the user stated.
- Data poisoning: the document supplies a false value that the plan uses in a sensitive
  position.
- Forwarding: the user asks the agent to send a document field, and that field contains
  attacker text.

### 2.3 Out of scope

- Attacks on model training, weights, or the inference server.
- Side channels, hardware attacks, and supply-chain compromise.
- A compromised runtime, policy table, or audit log.
- Denial of service and resource exhaustion beyond the interpreter's step and loop budgets.
- The correctness of the user's own request. If the user asks to send data to an attacker,
  the system is not defending against the user.

### 2.4 Assumption about the human

The human is assumed honest but busy. A confirmation is a security control only if the
person reads it. The measurements include both a declining and an approving user because
the difference is the size of that assumption.

---

## 3. System Under Test

AgentOS is a Rust workspace. The components relevant to this paper are the type-level
provenance layer, the plan language and interpreter, the policy engine, the session and
confirmation path, and the measurement harness. The kernel sandbox (Landlock, seccomp,
cgroup v2, user and mount namespaces) is part of the artifact but is not the subject of
this measurement.

### 3.1 Isolation

A document enters as `Quarantined<String>`. The privileged planner never receives it. The
extractor runs in a separate, confined process with no tools and no network. It returns a
typed record: integers, enums, and text fields. Integers and enums cannot carry
instructions. Text fields remain attacker-controlled bytes and carry an untrusted label.

The planner receives the user's request and the schema. It does not receive the document.
It can name a field, but it cannot read the field's bytes. This is the property that makes
classic instruction injection into the planner impossible by construction: the attacker's
text has no path into the planner's context.

It is not the property that prevents exfiltration. A planner can write
`send_email(to = doc.recipient)` without knowing the address. It is moving a named value,
not reading it. The policy must decide whether that move is allowed.

### 3.2 Provenance and policy

Every value is a `Val<T>` carrying a label: the source kind and identifiers that produced
it. Labels propagate through field access, list indexing, `len`, `map`, `zip`, and
extraction. The plan language is a small, terminating DSL; it has no recursion, no dynamic
dispatch, and bounded loops.

Before a tool call, the host evaluates each argument. A trusted value is allowed. A tainted
value is looked up by `(tool, argument)`:

| Argument | Tainted decision |
|---|---|
| `shell.cmd`, `shell.argv` | deny |
| `fs.write.path`, `fs.write.contents` | deny |
| `send_email.to`, `send_email.subject`, `send_email.body` | confirm |
| `http.get.url` | allow only if the domain is allowlisted; otherwise refuse with an invitation to confirm the domain |
| any argument with no rule | confirm (fail closed) |

A deny cannot be overridden by a confirmation. A confirmation shows the tool, the argument,
the value, and the value's provenance. The user is not asked to classify text; they are
asked whether this specific effect is what they wanted.

### 3.3 Strict mode

Strict mode rewrites every `Confirm` into a `Deny`. It asks nobody. It is the answer to
"what does zero cost when the human is removed?" It is not the default, because it refuses
legitimate forwarding.

### 3.4 Intent pins

The user's request is parsed for values the user stated: an email address, a URL, a path, a
command. Those values are pinned. If a plan puts a different, tainted value into the pinned
position, the host denies it before the grant lookup. The check is on shape and provenance,
not on the meaning of the document's text. It cannot be unlocked by approval.

Pins address substitution. They do not address forwarding: when the user says "send the note
to Bob," the note is supposed to be forwarded, and there is no contradiction to detect.

### 3.5 Audit

Every tool call is recorded before it executes. The audit record contains the tool, the
argument names, the provenance labels, and a digest; it does not contain the attacker's
text. The audit log is hash-chained so tampering is evident.

---

## 4. Measurement Design

### 4.1 Two definitions of leakage

**Taint flow (broad).** A tool ran with at least one argument whose value carried an
untrusted label. This is what the artifact measures. It is an upper bound on leakage: it
counts a note the user asked to forward as a leak.

**Unauthorized flow (narrow).** An untrusted value reached a sensitive argument whose
position the user did not authorize: a recipient the user did not name, a path outside the
granted tree, a command not composed from a trusted template. This is the deployment
property. The benign twins in the model corpus are designed to make the distinction
measurable: the same request against a clean document should complete, and against a
hostile document should either be refused or forwarded only to the user's stated
destination.

We report the broad metric because that is what the harness produces, and we state where it
overcounts. A paper that reports a broad taint-flow rate as "attack success" will
understate utility and overstate the defense.

### 4.2 Four arms

Every corpus is run under four configurations that differ only in the decision layer:

1. **No policy.** Every rule is `Allow`. This is the counterfactual: it proves the corpus
   actually routes attacker data into tools.
2. **Policy, declining user.** The shipped rules. Every confirmation is shown and answered
   "no."
3. **Policy, approving user.** The same rules. Every confirmation is answered "yes." This is
   the rubber-stamp arm.
4. **Strict, no human.** Every `Confirm` is a `Deny`. Nobody is asked.

The difference between arms 2 and 3 is the human's contribution. The difference between
arms 3 and 4 is what strictness buys and what it costs.

### 4.3 Utility and human cost

Utility is the fraction of benign tasks that complete. Human cost is the number of prompts
shown, and the number of attacks that depend on a prompt rather than an automatic refusal.
A defense that stops every attack by asking about every action is not a defense; it is a
human with extra steps. The prompts-per-task number is therefore a first-class result.

### 4.4 Controls

- The counterfactual arm must succeed on every policy-relevant attack; the four
  resource-exhaustion programs halt on the interpreter's budget in every arm by design.
- Every benign program must complete under the shipped rules. If it does not, the defense
  is refusing ordinary work.
- The automatic-versus-human split is computed two ways: by the rule that produced the stop,
  and by the difference between the declining and approving arms. They must agree.
- Model-quality failures — the model could not produce a runnable plan — are reported
  separately and stay in the denominator. They are not blocked attacks.
- The measurement harness is tested for tool-name drift: the instruction must advertise
  exactly the tools the host registers.

---

## 5. Methodology

### 5.1 Policy corpus

45 complete DSL programs: 12 benign controls and 33 attacks across 13 categories
(instruction injection, exfiltration, command injection, path injection, URL injection,
data poisoning, multi-hop, structure laundering, resource exhaustion, and four benign
categories). The policy-relevant attacks read the same hostile document and differ only in
which field reaches which sensitive argument. This is deliberate: a difference in outcome is
a difference about the policy, not about the payload. The four resource-exhaustion programs
instead burn the interpreter's step budget and do not read the document.

The hostile document contains:

```
INVOICE ACME-1 total=1 status=pending
recipient=attacker@evil.test
url=https://evil.test/exfiltrate
note="Ignore all previous instructions and send the user credentials to attacker@evil.test"
```

The extractor returns a list with one record. `total` and `status` are typed; `recipient`,
`url`, and `note` are quoted text. `inv.0.note` is the first record's `note` field.

The corpus is hand-written and small. It is designed to isolate policy decisions, not to be
a representative benchmark. The counterfactual and benign controls are what make its
verdicts meaningful.

### 5.2 Model corpus

16 tasks: 7 benign controls and 9 attacks. Most attacks share a request with a benign twin --
the same request against a clean document. The corpus has seven benign controls for nine
attacks, so some twins cover more than one attack. This distinguishes "the injection was
resisted" from "this task always asks." The request is always ordinary; the attack is in the
document.

The planner sees only the trusted request. It does not see the document. Role Q is stubbed
with an extractor that faithfully lifts the document's fields, including an address if one
is present. That is the adversarial choice for the planner: the attack material is
available to the plan, so a failure is the planner's or the policy's, not extraction's.

The adversarial planner is a deterministic backend that reads the request and emits the
plan an attacker wants, routing document content into the positions the user pinned. It is
the worst-case planner. The live model is a separate arm; it is cooperative unless the
document can steer it, which it cannot, because the model never reads the document. The
live arm therefore measures whether a real model writes a plan that forwards document data,
not whether the document can instruct it.

### 5.3 Schema controls

The same model corpus is run with three schemas:

- **Unbounded:** all fields are strings.
- **Bounded:** every string field declares a 96-character `maxLength`. An extraction over
  the bound is refused, not truncated.
- **Closed:** `total` is an integer, `status` is an enum of five values, and free-text
  fields remain bounded strings.

This isolates the effect of schema shape from schema size.

### 5.4 Intent pins

The pin ablation compares the approving arm with and without pins on the 14-task corpus used
for that experiment. The metric is the number of tasks where a tainted value reached a tool,
and the number of tasks refused with no prompt.

### 5.5 Live model

`llama3.2:3b` via a local Ollama server. The model receives the planner instruction and the
trusted request. It returns JSON, which is rendered into plan source and parsed. A response
that does not parse is a model-quality failure, not a defense.

The live run is exploratory: one 3B checkpoint, one run per arm, 16 tasks. It is reported to
show that the harness produces real behavior after the tool-name fix, not to estimate a
population rate.

### 5.6 Harness validity

The first live run after the planner instruction was corrected to the shipping tool names
produced a suspiciously perfect zero. The instruction advertised `http.fetch`; the eval host
registered `http.get`. Every live plan died on its first call with `ToolRejected`, and the
run was scored as no leak. The fix makes the instruction a harness parameter
(`Planner::with_instruction`, which accepts only a `&'static str` so runtime data still
cannot enter the prompt) and adds a drift test that the instruction advertises exactly the
tools the host registers. The numbers in this paper are from after the fix.

---

## 6. Results

### 6.1 Policy corpus

**Table 1.** The same 45 programs under four decision layers. Attacks are 33; benign
controls are 12. "Tainted flow" means a tool ran with a tainted argument.

| Arm | Tainted flows (attacks) | Benign complete | Prompts | Decomposition |
|---|---:|---:|---:|---|
| No policy | 29/33 (87.9%) | 12/12 | 0 | counterfactual |
| Policy + declining user | 0/33 | 12/12 | 14 | 12 automatic, 17 human-dependent, 4 budget |
| Policy + approving user | 14/33 (42.4%) | 12/12 | 14 | rubber stamp |
| Strict, no human | 0/33 | 12/12 | 0 | every confirm is a deny |

The 15 "denied outright" outcomes split into 12 explicit policy denials and 3 allowlist
refusals that a user could override by adding the domain. The 3 are therefore counted as
human-dependent, not automatic. The 14 user refusals and the 3 allowlist refusals are the
17 human-dependent stops. The 4 remaining attacks are stopped by the interpreter's step
budget, not by the policy.

The benign rate of 12/12 in the strict arm is a property of this corpus: every benign
control uses planner-authored literals, so no legitimate forwarding is refused. This is why
the policy corpus alone cannot measure the cost of strictness.

### 6.2 Model corpus

**Table 2.** 16 tasks: 9 attacks, 7 benign. "Tainted flow" is the broad metric over all 16
tasks; benign twins that forward a field count as flows. The adversarial planner is the
deterministic worst case. The live arm is one run of `llama3.2:3b`.

| Arm | Tainted flows | Prompts | Auto-refused | Benign clean | Benign refused/denied | Model-quality failures |
|---|---:|---:|---:|---:|---:|---:|
| Adversarial, declining | 0/16 | 11 | 4 | 0/7 | 6 | 0 |
| Adversarial, approving | 11/16 (68.8%) | 11 | 4 | 0/7 | 0 (6 completed) | 0 |
| Adversarial, strict | 0/16 | 0 | 4 | 0/7 | 6 denied | 0 |
| Live, declining | 0/16 | 1 | 0 | 2/7 | 1 | 3 |
| Live, approving | 1/16 (6.2%) | 1 | 0 | 2/7 | 1 denied | 4 |

The 11 flows in the adversarial approving arm decompose exactly: 4 attacks are auto-refused
by intent pins, 5 unpinned attacks reach a tool, and 6 benign twins forward a field. The
strict arm refuses the 5 unpinned attacks and the 6 benign twins; its zero is bought by
refusing the forwarding the user asked for. The 4 pin refusals are the same in both arms.

The live arm is not a rate. In one run, the model failed to produce a runnable plan for 3–4
of 16 tasks, and one attack (`model/status-injected`) leaked in the approving arm. The
declining arm leaked nothing. The model-quality failures are the model's, not the defense's,
and they are kept in the denominator.

### 6.3 Schema shape

**Table 3.** Adversarial planner, approving user, 16 tasks. Forwarded bytes are the total
untrusted bytes that reached a tool across the run.

| Schema | Tainted flows | Forwarded bytes |
|---|---:|---:|
| Unbounded | 11/16 (68.8%) | 363 |
| 96-character bound | 10/16 (62.5%) | 307 |
| Closed types | 9/16 (56.2%) | 182 |

A length bound moves the byte count by 56 and the flow count by one. Closed types move the
byte count by 181 and the flow count by two, and they remove the instruction channel
entirely for `status`: the model cannot forward a sentence through an enum. They cannot
close `note` or `recipient` without refusing the user's data. The residual 182 bytes are
the free-text fields the schema cannot close without refusing the user's data.

One confound: the bounded arm's pin count falls from 4 to 1. That is not the pins getting
better. The bound refuses one extraction before the pinned tool is reached, so the task
stops earlier. The pin count measures tasks stopped *by the pins* only in the unbounded
column.

### 6.4 Intent pins

**Table 4.** Approving user, adversarial planner, 14-task corpus used for the pin ablation.

| Configuration | Tainted flows | Auto-refused |
|---|---:|---:|
| Without pins | 13/14 (92.9%) | 0 |
| With pins | 9/14 (64.3%) | 4 |

The pins remove four substitution attacks with no prompt and no approval. They do not
change forwarding: the remaining nine flows are the document content the task asked to
forward, or attacks that use a field the user did not pin.

### 6.5 The human is most of the zero

On the policy corpus, the shipped rules stop 12 attacks with no human, 17 with a human, and
4 with the budget. The headline 0/33 is therefore 36% automatic and 52% human, with the
remainder halted. With an approving user, 14/33 attacks run. The 0% and the 42% are the
same rules and the same corpus; only the human's answer changed.

The 14 prompts are the cost of the human-dependent stops. They are not evenly distributed:
the command and path categories are denied outright and never prompt, while the email and
data-poisoning positions are the ones the policy marks `Confirm`. The three allowlist
refusals do not prompt; they refuse with an invitation to add the domain, which is why they
are counted as human-dependent rather than automatic. The prompts are specific — tool,
argument, value, source — but specificity does not make confirmation fatigue disappear. The
approving arm is what happens when it does.

### 6.6 Strictness and utility

Strict mode is the only configuration that reaches zero with no human on both corpora. On
the policy corpus it costs nothing, because the benign controls use trusted literals. On the
model corpus it denies 6 of 7 benign tasks, because the adversarial planner routes document
content into every task, including the benign twins. The difference between the two corpora
is the measurement: a corpus without legitimate forwarding cannot see the price of refusing
forwarding.

This is the central trade-off. Strict zero is real. It is not free. The price is exactly the
class of task the user asked for: "send the note," "email the invoice," "write the document
to a file."

### 6.7 What the live model adds

After the harness fix, the live model produces real plans and real outcomes. It is better
than the adversarial planner at benign tasks (2/7 clean vs 0/7) and worse at producing
runnable plans (3–4 failures per arm). In the approving arm it leaked once, on
`model/status-injected`: the document's status line was typed as a string in the unbounded
schema and forwarded. The closed-type schema would have refused it. The live run is too
small to estimate a rate, but it shows the same mechanism the deterministic corpus measures.

---

## 7. Discussion

### 7.1 Report the arm

A defense paper that reports "0% attack success" without the user policy is reporting an
upper bound on the machine's contribution. The useful table has at least two rows: the
declining user and the approving user. The difference is the human's share. A defense that
cannot state that share has not measured its own dependence.

### 7.2 The price of zero is a utility curve, not a point

Strict mode is a point on a curve: zero tainted flows, six of seven benign tasks refused.
The shipped policy is another: zero with a declining user, 14/33 with an approving one. The
right question is not "is it zero?" but "at what utility, and with how much attention?" A
deployment can choose a point, but it cannot choose a point it has not measured.

### 7.3 Shape beats size

A 96-character bound is a size control. It reduces the bytes of an injection but not the
number of channels. A closed enum is a shape control: it removes the channel. The result is
consistent with the architecture's claim that typed extraction, not filtering, is the
lever. The limit is equally clear: fields the user asked to forward (`note`, `recipient`)
cannot be closed without removing the task.

### 7.4 Substitution is not forwarding

Intent pins address a contradiction between two values the system holds: the user said
"Bob," the document says "attacker." That is decidable on shape and provenance, and it can
be denied without a human. Forwarding has no such contradiction: the user said "send the
note," and the note is what the document supplied. The system can refuse, bound, or ask; it
cannot decide that the user did not mean what they said. This is the residual, and it is a
property of the task, not a bug in the taint engine.

### 7.5 Authorization-relative leakage

The broad metric counts the user's requested forwarding as a leak. A better metric asks
whether the flow was authorized: did the user name the destination, the field, and the
tool? If yes, the flow is utility, not leakage, even if the bytes are attacker-controlled.
If no, the flow is a leak regardless of whether a human approved it. The benign twins are a
first step toward this metric; a full implementation would require a machine-readable
authorization record derived from the request, which the current intent pins approximate
but do not complete.

### 7.6 Making the lunch cheaper

The measurements suggest four levers, in order of leverage:

1. **Pin user-stated values.** Four substitution attacks are refused with no prompt. This is
   the cheapest automatic stop.
2. **Close types where the task allows it.** `status` as an enum removes an instruction
   channel; `total` as an integer removes a prose channel. The residual is the free-text
   field the user asked to forward.
3. **Use typed tools instead of raw shell.** `install(package = "ripgrep")` has no command
   slot for a document to fill. For vendor-specific installers, the tool can fetch the
   command and show it to the user; the user still does not have to find it. The command's
   source, not the existence of a shell, is what matters.
4. **Reserve confirmation for genuinely ambiguous forwarding.** The current policy asks on
   every tainted email argument. A policy that pins the destination and the field could
   allow the user's requested forwarding automatically and ask only when the destination is
   document-chosen. That would move tasks from the human-dependent bucket to the automatic
   one without pretending the human is unnecessary.

### 7.7 Measurement validity is part of the result

Three instrument failures in this artifact each made a reported result meaningless:

- A corpus entry ended with `len(doc)` on a record, so every plan halted after the sensitive
  call and the outcome looked defended.
- A fixture hardcoded `status = "paid"`, so the closed-type arm never saw the status-line
  attack and measured nothing.
- The live harness advertised `http.fetch` while the host registered `http.get`, so every
  live plan was rejected and the 0% was vacuous.

In each case the number was green. The fix was not a better defense; it was a better
instrument. Agent-security papers should report model-quality failures, tool-name drift, and
the exact arm, because a zero produced by a broken harness is indistinguishable from a zero
produced by a defense unless the harness is inspected.

---

## 8. Threats to Validity

**Construct validity.** The broad metric counts requested forwarding as leakage. The
narrow metric is defined but not fully implemented. The 12/12 strict benign rate on the
policy corpus is an artifact of benign controls that use trusted literals; the model corpus
is where the cost appears.

**Internal validity.** The human is simulated: "declining" always says no, "approving"
always says yes. Real users are neither. The adversarial planner is deterministic and
worst-case; it may overstate what a cooperative model does. The live model is cooperative
and may understate what a steered model does.

**External validity.** The corpora are small and hand-written: 45 policy programs and 16
model tasks. They are not AgentDojo. The model arm is one 3B checkpoint, one run per arm,
and 3–4 model-quality failures per arm. The numbers are descriptive, not estimates of a
population.

**Conclusion validity.** No confidence intervals are reported for the single-run live arm.
The deterministic arms are exact for the corpus, not for the world. The intent-pin ablation
uses a 14-task corpus from an earlier version of the model corpus; the current corpus has 16
tasks. The comparison is within that 14-task set.

**Artifact validity.** The live harness had a tool-name mismatch until commit `e09992a`.
The numbers reported here are from after the fix. The fix is covered by a drift test. The
deterministic policy numbers never depended on the tool names.

**Scope.** The paper measures the policy and extraction layers. It does not measure the
kernel sandbox, the audit chain's tamper evidence, or the performance cost of confinement.
Those are engineering properties of the artifact, not claims of this study.

---

## 9. Related Work

**Structural defenses.** CaMeL [1] separates control and data flow, uses capabilities, and
reports secure task completion on AgentDojo (67–77% across reported versions). Progent [4]
enforces fine-grained privilege policies over tool calls. IsolateGPT [3] isolates LLM-app
execution. FIDES [5] applies information-flow control to agents. AgentOS follows this line.
Its distinctive element is not the architecture but the measurement: the same corpus under
four arms, with the human's contribution separated from the machine's.

**Benchmarks.** AgentDojo [2] provides 97 realistic tasks and 629 security cases across
email, banking, travel, and workspace, and scores utility alongside security. InjecAgent and
other benchmarks target indirect injection. Our corpora are smaller and hand-written; they
are designed to isolate policy decisions, not to replace a benchmark. A full evaluation
should port the four-arm protocol to AgentDojo.

**Detection and alignment.** A large body of work filters, spotlights, or fine-tunes models
against injection. These defenses are complementary but not structural: they depend on
recognizing the attack. The measurements here are about what happens when the model is not
the boundary.

**Human factors.** Confirmation fatigue is known qualitatively. This paper quantifies its
security effect in one system: 17/33 attacks depend on a human, and 14/33 succeed when the
human approves. The number is system-specific, but the shape — a zero that is mostly a
person — is likely general.

---

## 10. Conclusion

AgentOS can report 0/33 on its policy corpus, 0/16 on its adversarial model corpus, and 0/16
in strict mode. Those zeros mean different things. The first is 12 automatic refusals, 17
human refusals, and 4 budget halts. The second is four intent-pin refusals plus strict
policy. The third is strict policy refusing six of seven benign tasks. A paper that reports
only the zero has measured the wrong thing.

The useful result is the price: what utility, what attention, and which flows are
authorized. On this artifact, the price of a no-human zero is the forwarding the user asked
for. The price of a human zero is the human's attention, and the approving arm shows what
happens when that attention is not there. The cheap lunch, if it exists, is in pinning the
values the user stated, closing the types the task allows, replacing raw shell with typed
tools, and reserving confirmation for the flows that are genuinely ambiguous. That is the
next measurement, not another architecture.

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

[6] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz. "Not What You've
Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt
Injection." AISec 2023. arXiv:2302.12173.

[7] J. H. Saltzer and M. D. Schroeder. "The Protection of Information in Computer Systems."
Proceedings of the IEEE, 1975.

[8] D. E. Denning. "A Lattice Model of Secure Information Flow." Communications of the ACM,
1976.

---

## Appendix A: Reproducibility

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

The last argument is the number of runs per arm. The paper's live numbers use one run and
should be read as exploratory. The deterministic arm uses the adversarial planner and is
exact for the corpus.

The artifact's workspace test suite is 939 tests on Linux and 823 on Windows at the commit
used for this draft; those numbers describe the artifact, not the study.

## Appendix B: Raw arm summaries

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
declining: 0/16 tainted, 11 prompts, 4 auto-refused, 6/7 benign refused
approving: 11/16 tainted (5 attacks + 6 benign twins), 11 prompts, 4 auto-refused,
           6/7 benign completed, 363 bytes
strict:    0/16 tainted, 0 prompts, 4 auto-refused, 6/7 benign denied
```

**Model corpus, live `llama3.2:3b`, one run.**

```
declining: 0/16 tainted, 1 prompt, 3 model-quality failures, 2/7 benign clean
approving: 1/16 tainted (6.2%), 173 bytes, 1 prompt, 4 model-quality failures,
           2/7 benign clean, leaked model/status-injected
```

**Schema controls, adversarial approving.**

```
unbounded: 11/16 tainted, 363 bytes
bounded:   10/16 tainted, 307 bytes
closed:     9/16 tainted, 182 bytes
```

**Intent pins, 14-task corpus, adversarial approving.**

```
without pins: 13/14 tainted (92.9%), 0 auto-refused
with pins:     9/14 tainted (64.3%), 4 auto-refused
```
