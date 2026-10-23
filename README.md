# AgentOS

A security-focused agent runtime. The design goal is narrow: an attacker who controls a web
page, an email, or a tool output must not be able to influence what the privileged model
does.

This repository is a **research artifact**, not a production system.

## Paper

- [What Does 0% Mean? A Four-Arm Protocol for Evaluating Prompt-Injection Defenses](paper/what-does-zero-mean.md)
- [PDF](paper/what-does-zero-mean.pdf)
- [Case-study technical report](paper/price-of-zero.md)

The paper evaluates AgentOS as a case study. It does not claim a new architecture; it
proposes a protocol for measuring what a reported 0% actually costs.

## What is here

`agentos-types` provides `Val<T>`, `Label`, `Trusted<T>`, and `Quarantined<T>`.
`agentos-dsl` is a small plan language with provenance propagation. `agentos-policy`
implements per-argument rules keyed on provenance. `agentos-core` contains the session and
controller. `agentos-sandbox` implements Landlock, seccomp, cgroup v2, and user/mount
namespace confinement on Linux. `agentos-eval` contains the measurement harness.

## Build and test

Windows: use the wrapper, not bare `cargo`.

```powershell
.\cargo.ps1 test
.\cargo.ps1 clippy --all-targets
```

Linux/WSL:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets
```

The sandbox, cgroup, and namespace tests are Linux-only. The cgroup tests need a delegated
cgroup; run them inside a systemd user scope:

```bash
systemd-run --user --scope -- bash -lc 'cargo test -p agentos-sandbox'
```

## Reproduce the paper's numbers

```bash
cargo run -p agentos-eval --bin agentos-eval -- --verbose
cargo run -p agentos-eval --bin agentos-model-eval --features=ollama -- --deterministic-only
```

The live model arm needs Ollama with `llama3.2:3b`:

```bash
ollama serve
cargo run -p agentos-eval --bin agentos-model-eval --features=ollama -- llama3.2:3b 1
```

## Status and limits

The paper documents the limits: small self-authored corpora, simulated users, one 3B model
for the live arm, no formal proof, and a broad taint-flow metric that overcounts requested
forwarding. See `paper/what-does-zero-mean.md` §7.

## License

- Code: MIT (`LICENSE`).
- Paper: CC BY 4.0 (`paper/LICENSE`).

## Citation

```bibtex
@misc{bozkurt2026zero,
  author = {Emre Bozkurt},
  title  = {What Does 0\% Mean? A Four-Arm Protocol for Evaluating Prompt-Injection Defenses},
  year   = {2026},
  note   = {Technical report},
  url    = {https://github.com/FlyingGrasss/agent-os}
}
```
