---
description: Break the current AgentOS change into independent work items and dispatch each to a subagent in parallel, then review and integrate.
agent: build
---

$ARGUMENTS

## Method

Use the `task` tool to fan out. This is only worth doing when the work
genuinely divides; if the request is one coherent edit, just do it.

1. **Read the request and identify the boundaries.** Split along lines that do
   not share files where possible. Two subagents editing the same file will
   conflict, so if the work is not separable, do not force parallelism.

2. **Pick the right agent per item.**

   - `rust-impl` for portable Rust: provenance, the interpreter, policy rules,
     pager, core.
   - `linux-sandbox` for Landlock, seccomp, cgroup, namespaces, fd passing.
     Note that this agent cannot verify anything on a Windows host.
   - `security-reviewer` for adversarial review of an existing change. Read
     only, no edits.
   - `explore-agentos` for locating enforcement points and call sites. Read
     only.

3. **Dispatch in one message.** Multiple `task` calls in a single message run
   concurrently. Do not dispatch them one at a time; that defeats the purpose.

4. **Give each subagent its full context.** It starts with a fresh context and
   cannot see this conversation. Include which files it owns, what the
   conventions are, and how to build. Do not say "as discussed above".

5. **Do not duplicate their work yourself.** While they run, do something
   non-overlapping or nothing.

6. **Integrate and verify.** Read the actual diffs. Then run the tests
   yourself with `.\cargo.ps1 test -p <crate>`. Do not relay a subagent's claim
   that something compiles or passes; check it.

## Constraints to pass on

Subagents do not read this session's context, so restate the ones that apply:

- Build with `.\cargo.ps1`, never bare `cargo`. This host has no Windows SDK.
- Preserve files as UTF-8.
- Use the `git` and `gh` CLIs freely, but never push unverified work: test
  first, then `git status` and the diff, then commit.
- Every code change ships with the test that proves the untrusted path still
  cannot reach a sensitive position.

## Afterwards

Report what changed, what was verified by running tests versus only asserted,
and anything a subagent got wrong or left unfinished.