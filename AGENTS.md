# AgentOS

A security-focused agent runtime. The design goal is narrow and testable: an
attacker who fully controls a web page, an email, or a tool's output must not be
able to influence what the privileged model does.

## Core invariants

These are the load-bearing claims. Each one is meant to have tests that fail if
it is broken.

- **I1** No untrusted bytes ever enter the Controller's LLM prompt.
- **I2** The quarantined processor has no tools, no network, and no filesystem
  access beyond its input.
- **I3** Every value carries a provenance label, and labels propagate through all
  operations.
- **I4** Sensitive tool arguments reject tainted values unless the user confirms.
- **I5** A tool process can access only the file descriptors it was handed.
- **I6** Every action is recorded in an append-only audit log before it executes.

## Build and test

This host is Windows 11 without the Windows SDK, so the MSVC target cannot link
(LNK1181 on `kernel32.lib`). Use the wrapper script, which selects the GNU
toolchain and puts MinGW-w64 on PATH:

```powershell
.\cargo.ps1 test              # whole workspace
.\cargo.ps1 test -p agentos-dsl
.\cargo.ps1 clippy --all-targets
```

Do not run bare `cargo` in PowerShell; it will fail to link. Do not add
`.cargo/config.toml` overrides, the wrapper handles it.

The sandbox, cgroup, and eBPF phases target Linux and build under WSL2 with a
native `x86_64-unknown-linux-gnu` toolchain. Code in those crates should be
`#[cfg(target_os = "linux")]` and must not be expected to run on this host.

## Layout

| Crate | Role |
|---|---|
| `agentos-types` | `Val<T>`, `Label`, `Trusted<T>`, `Quarantined<T>`, `Cap<K>` |
| `agentos-dsl` | Plan language: parser, interpreter, taint propagation |
| `agentos-policy` | Per-argument rules keyed on provenance |
| `agentos-core` | Daemon, session actors, controller state machine |
| `agentos-infer` | Inference backends, roles P and Q, constrained decoding |
| `agentos-sandbox` | Landlock / seccomp / cgroup spawn, fd passing |
| `agentos-tools` | Built-in tools |
| `agentos-events` | eBPF programs and userspace decoder |
| `agentos-pager` | Context pager, L1/L2/L3 tiers |

## How the types enforce I1 and I3

`Trusted<T>` is a separate type, not a flag. Prompt assembly accepts only
`Trusted<T>`, so the compiler rejects any attempt to interpolate tainted text
into a prompt. `Val<T>` carries the label structurally, so `map` and `zip`
propagate taint without the author having to remember.

`Quarantined<T>` holds free text from an untrusted source. Grammar-constrained
decoding guarantees the *shape* of extracted data, not its safety, so quarantined
text is deliberately unreadable by the Controller. It can be shown to the user or
explicitly confirmed, and confirmation is the only path to a prompt.

## Adding a tool

1. Declare it with typed arguments and outputs; derive `schemars` for the schema.
2. Add explicit policy rules for **every** sensitive argument. An absent rule
   defaults to `Confirm`, so a new tool fails closed rather than open.
3. Policy decisions are per `(tool, argument)` and keyed on the argument's label.
   A tainted value in a shell argument or write path is denied outright;
   confirmation cannot override a deny.

## Use subagents aggressively

Parallelism is the default, not an optimization. Dispatch subagents for
substantive work rather than doing it inline, and dispatch independent items
**in a single message** so they run concurrently. Waiting on them one at a time
defeats the purpose.

- **Split by file ownership.** Two agents editing the same file will conflict.
  Before fanning out, decide which files each agent owns and say so in its
  prompt. If the work does not separate cleanly along file boundaries, do not
  force parallelism on that item.
- **Give every subagent full context.** It starts with a fresh context and
  cannot see this conversation. Include which files it owns, the conventions
  above, and the build command. Never write "as discussed above".
- **Never duplicate a dispatched agent's work.** While they run, do
  something non-overlapping or nothing.
- **Verify their claims yourself.** Run the tests and read the diffs. Do not
  relay a subagent's claim that something compiles or passes; check it. Their
  reports are leads, not evidence.
- **Do not trust a subagent's security conclusions.** A subagent that says
  the code is sound has read some of it. For anything load-bearing, read the
  enforcement point yourself.
- **Send independent investigations in one batch.** Verification, research,
  and review that touch different crates or different files should all be in
  flight together, not serialised.

Available agents: `rust-impl` (portable Rust), `linux-sandbox` (Landlock,
seccomp, cgroups, namespaces, eBPF), `security-reviewer` (read-only
adversarial review), `explore-agentos` (read-only search).

Do not use a subagent for work that is faster to just do, such as reading one
file to answer a one-line question, or running a single test command.

## Working conventions

Carried over from earlier work, still applicable:

- Preserve files as UTF-8.
- Use the `git` and `gh` CLIs freely. Creating repos, branching, committing,
  pushing, and reading history are part of the job, not something to ask about
  first.
- Do not commit or push until the work is verified: run the tests, then inspect
  `git status` and the diff, then commit. Never push broken code.
- Never commit secrets, keys, or credentials. Check `git status` for anything
  sensitive before staging.
- Do not force-push, rewrite published history, or amend someone else's commit.
  Ask first if a task seems to need it.
- Do not add generated or machine-local files to the repo: `target/`, build
  output, editor state, or the cached MSVC environment in `target/vcenv.txt`.
- Keep verification proportional to the change. Run the targeted test for the
  crate you touched; do not run the full workspace suite or a release build as a
  routine check. Do not run several redundant verification commands when one
  targeted command suffices.

## Tests as security assertions

Tests in this repo are not just regression coverage, they are the invariant
spec. When you add a capability, a new `Expr` variant, or a new tool argument,
add the test that proves the untrusted path still cannot reach a sensitive
position. Prefer a test that fails loudly over one that asserts on an error
message.
