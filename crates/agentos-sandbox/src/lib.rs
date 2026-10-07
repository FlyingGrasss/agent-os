//! Landlock confinement for AgentOS tool processes.
//!
//! Invariant **I5**: "a tool process can access only the file descriptors it was
//! handed." Landlock is the filesystem half of that story: it makes every path
//! the tool was *not* granted unreachable, so a hostile tool output that talks
//! the tool into reading `~/.ssh/id_rsa` gets `EACCES` instead of a file.
//!
//! Landlock constrains *path-based* access. It cannot revoke a descriptor the
//! child already holds across `exec`, so I5 is completed elsewhere (by handing
//! the child a deliberately small fd set) - see [`confine`]'s module docs for
//! the full list of what is **not** confined here.
//!
//! # Fail closed, always
//!
//! The rule for this crate is one line: **if a required enforcement layer is
//! unavailable, return an error instead of running unconfined.** A sandbox that
//! quietly gives up is worse than no sandbox, because the user believes they are
//! protected. Every constructor here is fail-closed:
//!
//! - filesystem access is denied by default; a grant is an explicit widening;
//! - TCP bind/connect is denied by default;
//! - `Scope::Signal` and `Scope::AbstractUnixSocket` are on by default;
//! - if the kernel ABI is too old for a requested right, [`Confine::apply`]
//!   fails with [`ConfineError::AbiTooOld`] listing exactly which rights are
//!   missing;
//! - if `PR_SET_NO_NEW_PRIVS` cannot be set, or sets but does not read back,
//!   [`Confine::apply`] refuses;
//! - if the kernel reports a partially applied ruleset, [`Confine::apply`]
//!   refuses.
//!
//! There is no "best effort" mode and no `if landlock_is_available()` guard for
//! the caller to forget.
//!
//! # ABI fallback matrix
//!
//! Landlock is versioned by ABI, not by kernel release string, and each version
//! adds access rights. The table below is the complete decision matrix. "Refuse"
//! means [`Confine::apply`] returns an error and the caller must not spawn the
//! tool. There is no "degrade loudly" row, because there is no safe way to
//! degrade: every right here is either part of the promised profile or a hole
//! in it.
//!
//! The rights-handled set is derived from `TARGET_ABI` ([`abi::Abi::V7`]) rather
//! than from the running kernel, so a given binary produces the same ruleset on
//! every host. A newer kernel is clamped *down* to V7: unknown rights stay off.
//!
//! | Capability | Landlock right | Min ABI | Linux | If missing | Why refuse |
//! |---|---|---|---|---|---|
//! | Landlock present at all | - | V1 | 5.13 | **Refuse** (`LandlockUnavailable`) | Nothing can be enforced; running unconfined would be a lie |
//! | Read a file | `LANDLOCK_ACCESS_FS_READ_FILE` | V1 | 5.13 | **Refuse** | Base confinement |
//! | List a directory | `LANDLOCK_ACCESS_FS_READ_DIR` | V1 | 5.13 | **Refuse** | Base confinement |
//! | Execute a file | `LANDLOCK_ACCESS_FS_EXECUTE` | V1 | 5.13 | **Refuse** | A tool that cannot map its own binary cannot run |
//! | Write a file | `LANDLOCK_ACCESS_FS_WRITE_FILE` | V1 | 5.13 | **Refuse** | Base confinement |
//! | Remove / make (all object kinds) | `LANDLOCK_ACCESS_FS_REMOVE_*`, `..._MAKE_*` | V1 | 5.13 | **Refuse** | Base confinement |
//! | Rename or link across directories | `LANDLOCK_ACCESS_FS_REFER` | V2 | 5.19 | **Refuse** | A `ReadWrite` grant that silently cannot rename is not the grant that was asked for |
//! | Truncate (`O_TRUNC`, `ftruncate`) | `LANDLOCK_ACCESS_FS_TRUNCATE` | V3 | 6.2 | **Refuse** | `File::create` and `truncate(2)` would fail at runtime, inside the tool |
//! | TCP bind / connect | `LANDLOCK_ACCESS_NET_BIND_TCP`, `..._CONNECT_TCP` | V4 | 6.7 | **Refuse** | This is the only egress control available; without it the tool is not offline and we must say so |
//! | ioctl on device files | `LANDLOCK_ACCESS_FS_IOCTL_DEV` | V5 | 6.10 | **Refuse** | Deny-by-default needs the whole V7 set handled; this is the floor |
//! | Signal processes outside the domain | `Scope::Signal` | V6 | 6.12 | **Refuse** | Otherwise a hostile tool can `kill()` the daemon |
//! | Connect to abstract UNIX sockets | `Scope::AbstractUnixSocket` | V6 | 6.12 | **Refuse** | Otherwise a tool can reach a sibling agent's socket |
//! | `restrict_self` log flags | `LANDLOCK_RESTRICT_SELF_LOG_*` | V7 | 6.15 | **Refuse** if requested | Only affects audit logging; unused here, listed for completeness |
//! | Restrict all threads (TSYNC) | `LANDLOCK_RESTRICT_SELF_TSYNC` | V8 | 7.0 | **Refuse** if requested | Not exposed: AgentOS confines a freshly forked single-threaded child, so TSYNC is unnecessary |
//! | Connect to a peer via inherited UNIX socket | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` | V9 | 7.1 | **Refuse** | Not implemented; on a V9 kernel a peer holding a connected socket could reach into the child |
//! | Kernel ABI newer than V7 | - | - | - | **Accept**, clamped to V7 | Unvetted rights stay disabled |
//! | `PR_SET_NO_NEW_PRIVS` | `prctl(2)` | always | - | **Refuse** | `landlock_restrict_self` returns `EPERM` without it; with `CAP_SYS_ADMIN` instead, a setuid exec could shed the ruleset |
//! | cgroup v2 limits | - | - | - | **Not used** | Not delegable to an unprivileged uid on the target host |
//! | user / mount namespaces | - | - | - | **Not used** | `unshare(CLONE_NEWUSER)` is denied for uid 1000 on the target host |
//!
//! The practical consequence: **AgentOS requires Landlock ABI V6 (Linux 6.12) or
//! newer to confine any tool at all.** The filesystem half alone would only need
//! V5, because denying the whole V7 set means handling `IOCTL_DEV` (V5); but the
//! default profile also turns on `Scope::Signal` and `Scope::AbstractUnixSocket`,
//! both V6, and a tool that can signal the daemon is not confined in any sense
//! that matters. So V6 is the floor, and it is a refusal, not a downgrade.
//!
//! Supporting older kernels would mean either handling a smaller right set (a
//! silent hole) or carrying a second, separately audited code path. Neither is
//! worth it: an operator who hits this error should see "this host is too old to
//! run AgentOS tools safely", not a quietly weaker sandbox.
//!
//! # Network egress: what is and is not covered
//!
//! [`Confine::allow_tcp_bind`] and [`Confine::allow_tcp_connect`] map to
//! `LANDLOCK_ACCESS_NET_BIND_TCP` / `LANDLOCK_ACCESS_NET_CONNECT_TCP`. These are
//! **port-scoped and nothing else**:
//!
//! - they are gated for TCP only. UDP, raw sockets, ICMP, SCTP, DCCP and every
//!   other protocol are unaffected;
//! - `socket(2)` itself still succeeds. A confined process can create sockets,
//!   it just cannot bind or connect them over TCP;
//! - rules match a port number on any address, not a specific peer, so "connect
//!   to 443" allows connections to any host on port 443;
//! - port `0` in a bind rule means the whole ephemeral range from
//!   `/proc/sys/net/ipv4/ip_local_port_range`.
//!
//! So a profile that gates TCP is **not** a profile that makes a tool offline.
//! Making a tool genuinely offline additionally needs a seccomp filter denying
//! `socket`/`socketpair`, which this crate does not yet install.
//!
//! # Example
//!
//! ```no_run
//! use agentos_sandbox::{Confine, ConfineError};
//!
//! // A tool that may read and run its own install tree, write one scratch
//! // directory, and talk to exactly one TCP port.
//! fn confine_tool(tool_dir: &str, scratch: &str, upstream_port: u16) -> Result<(), ConfineError> {
//!     Confine::new()
//!         .read_only_exec(tool_dir)
//!         .read_write(scratch)
//!         .allow_tcp_connect(upstream_port)
//!         .apply()?;
//!     // Only reached once the kernel has confirmed full enforcement, and
//!     // PR_SET_NO_NEW_PRIVS is in force. Safe to exec the tool now.
//!     Ok(())
//! }
//! ```
//!
//! On a non-Linux target [`Confine::apply`] returns
//! [`ConfineError::UnsupportedPlatform`], so cross-platform code compiles
//! without a `cfg` at every call site.
//!
//! # Testing
//!
//! The tests that matter are in `tests/escape.rs`: they re-exec the test binary,
//! confine the child, and assert that escape attempts actually fail. Unit tests
//! here cover only the ABI arithmetic, deliberately never calling `apply()` -
//! confining a `#[test]` thread would poison the test harness.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod abi;
mod confine;
mod error;
mod grants;

pub use abi::{detect as detect_kernel_support, Abi, Feature, KernelSupport, TARGET_ABI};
pub use confine::{Confine, Enforced};
pub use error::{ConfineError, SeccompError};
pub use grants::{FsGrant, NetGrant, ReadOnly, ReadOnlyExec, ReadWrite};

/// Passing capabilities to a worker as real descriptors.
#[cfg(unix)]
pub mod fdpass;
// `SeccompApplied` and `apply_seccomp` only exist on Linux. Off Linux the module
// still compiles to nothing usable, which is deliberate: a caller that asks for
// a seccomp profile on Windows gets a compile error rather than a filter that
// was never installed.
#[cfg(target_os = "linux")]
pub use seccomp::{Profile as SeccompProfile, SeccompApplied, apply_seccomp};

mod seccomp;