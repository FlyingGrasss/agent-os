---
description: Writes a new AgentOS tool end to end: typed arguments, policy rules for every sensitive argument, a schema, and the tests proving a tainted argument cannot reach a sensitive position without confirmation.
agent: build
---

Add a new tool to AgentOS. Follow $ARGUMENTS.

## Method

1. **Find the contract first.** Read the `ToolHost` trait in
   `agentos-dsl/src/interp.rs` and an existing tool to match the conventions.
   Decide the typed input and output. Derive `schemars` on the argument types so
   the schema is generated rather than hand-written.

2. **Classify every argument.** For each argument, decide its rule:

   - `Deny` for shell argv, write paths, and anything that selects a file or
     command. Confirmation must not be able to override a `Deny`.
   - `Confirm` for recipients, message bodies, subjects: anything that moves data
     to the outside world where a human should see it first.
   - `Allowlist` for URLs, so a tainted URL only reaches an allowlisted host.
   - `Allow` only where the argument cannot cause harm and the value is
     structurally bounded.

   Register these in `PolicyEngine::default_rules`, or wherever the project's
   rules for this tool live. Add a comment saying why each sensitive argument
   has the rule it has.

3. **Add the rule, then add the tests.** The tests are the point. An absent rule
   defaults to `Confirm`, so the test that matters is not "trusted values pass"
   but "tainted values at each sensitive position are refused or require
   confirmation, per the rule".

## Tests to write

At minimum, for every argument classified `Deny` or `Confirm`:

- A tainted value at that position is refused (or demands confirmation).
- The same call with a trusted value succeeds.
- Taint survives the route into that argument. If the value passes through
  extraction or field projection first, prove the label is still there, because
  that is the step that fails in practice.

Add a case where two tainted sources combine, and confirm the provenance shown
to the user lists both.

## Verification

Run `.\cargo.ps1 test -p agentos-policy` and any other crate you touched. Read
the output. Report the real result.