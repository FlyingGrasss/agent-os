//! Capability probing for the kernel observer.
//!
//! # Why probe at all, and why report honestly
//!
//! eBPF program loading needs `CAP_BPF` (or `CAP_SYS_ADMIN`), the ability to
//! create BPF maps of a given size against `RLIMIT_MEMLOCK`, and a kernel with
//! BTF for CO-RE relocation. A deployment that assumes it has these and does
//! not will fail at load time with an errno that does not say which requirement
//! was missing.
//!
//! [`probe`] therefore reports each requirement separately with the observed
//! value, so the answer to "why is observation unavailable" is a list rather
//! than a single error string. Reporting a bare error here would push the work
//! of diagnosis onto whoever is trying to use the feature.
//!
//! # Nothing here attempts to load
//!
//! [`probe`] only reads. It never creates a map or loads a program, so running
//! it is side-effect free and safe to call during startup even when the answer
//! is "no".
//!
//! # Platform support
//!
//! The probe is compiled on all platforms. Off Linux it reports a single
//! "wrong platform" reason rather than pretending to check kernel features it
//! cannot see. The Linux path reads `/proc` and `/sys`; the values it reports
//! are read with plain `std::fs`, so it is testable in principle but is not
//! exercised on a Windows host.

/// One requirement, and whether it is met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// Stable identifier, so a caller can match on it without parsing text.
    pub id: &'static str,
    /// Human-readable detail: the observed value, or what was missing.
    pub detail: String,
    /// True when the requirement is satisfied.
    pub satisfied: bool,
    /// True when the check cannot be performed on this platform at all, as
    /// opposed to being performed and failing. These are different diagnoses:
    /// "we could not look" and "we looked and it is not there" lead to
    /// different fixes.
    pub indeterminate: bool,
}

impl Check {
    // Constructors for the satisfied and indeterminate cases are only reached
    // from the Linux readers and from tests; off Linux, every check is a
    // refusal. They stay in the type because a caller on any platform needs to
    // be able to build a Report for testing its own handling.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn ok(id: &'static str, detail: String) -> Self {
        Self { id, detail, satisfied: true, indeterminate: false }
    }

    fn no(id: &'static str, detail: String) -> Self {
        Self { id, detail, satisfied: false, indeterminate: false }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn unknown(id: &'static str, detail: String) -> Self {
        Self { id, detail, satisfied: false, indeterminate: true }
    }
}

/// The result of probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// True only if every check is satisfied. Any indeterminate check makes
    /// this false: "could not determine" is not availability.
    pub fn available(&self) -> bool {
        self.checks.iter().all(|c| c.satisfied)
    }

    /// Every unsatisfied check, each with its reason. This is the whole point
    /// of the probe: the caller gets the list of what is missing rather than a
    /// single opaque failure.
    pub fn blockers(&self) -> impl Iterator<Item = &Check> {
        self.checks.iter().filter(|c| !c.satisfied)
    }

    /// One-line summary suitable for a startup log.
    pub fn summary(&self) -> String {
        if self.available() {
            return "eBPF observation: available".to_string();
        }
        let mut s = String::from("eBPF observation: unavailable; ");
        let parts: Vec<String> = self.blockers().map(|c| format!("{}: {}", c.id, c.detail)).collect();
        s.push_str(&parts.join("; "));
        s
    }
}

/// Inspect the host and report what the kernel observer would need.
///
/// # What would be wrong if this failed
///
/// Every failure mode here leads to the same outcome: an agent that appears to
/// have syscall visibility but does not. That is worse than having no
/// observation at all, because the audit log would be silently incomplete and
/// the absence of violations would read as the absence of violations. So the
/// contract here is that [`Report::available`] is false unless every single
/// requirement was checked and met.
pub fn probe() -> Report {
    #[cfg(target_os = "linux")]
    {
        Report { checks: checks_linux() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Report {
            checks: vec![Check::no(
                "platform",
                "eBPF requires Linux; this build targets other platforms and no kernel features were checked"
                    .to_string(),
            )],
        }
    }
}

#[cfg(target_os = "linux")]
fn checks_linux() -> Vec<Check> {
    vec![
        cap_bpf(),
        cap_perfmon(),
        cap_sys_admin(),
        unprivileged_bpf(),
        btf_present(),
        memlock(),
    ]
}

/// Capability bit positions from `linux/capability.h`.
#[cfg(target_os = "linux")]
mod capbit {
    pub const CAP_SYS_ADMIN: u32 = 21;
    pub const CAP_PERFMON: u32 = 38;
    pub const CAP_BPF: u32 = 39;
}

#[cfg(target_os = "linux")]
fn cap_bpf() -> Check {
    cap_check("cap_bpf", capbit::CAP_BPF, "CAP_BPF is required to load BPF programs on kernel 5.8 and later")
}

#[cfg(target_os = "linux")]
fn cap_perfmon() -> Check {
    cap_check(
        "cap_perfmon",
        capbit::CAP_PERFMON,
        "CAP_PERFMON attaches perf events; on kernel 5.8 and later it covers CAP_BPF",
    )
}

#[cfg(target_os = "linux")]
fn cap_sys_admin() -> Check {
    cap_check(
        "cap_sys_admin",
        capbit::CAP_SYS_ADMIN,
        "CAP_SYS_ADMIN was the pre-5.8 requirement and is still honoured where CAP_BPF is absent",
    )
}

#[cfg(target_os = "linux")]
fn cap_check(id: &'static str, bit: u32, why: &str) -> Check {
    match read_cap_eff() {
        Ok(eff) => {
            if eff & (1u64 << bit) != 0 {
                Check::ok(id, format!("held (CapEff bit {bit} set); {why}"))
            } else {
                Check::no(id, format!("not held (CapEff bit {bit} clear); {why}"))
            }
        }
        Err(e) => Check::unknown(id, format!("could not read /proc/self/status: {e}; {why}")),
    }
}

/// Read the effective capability set from `/proc/self/status`.
#[cfg(target_os = "linux")]
fn read_cap_eff() -> Result<u64, std::io::Error> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:") {
            let hex = rest.trim();
            // A parse failure here means the format changed; surfacing it as an
            // error is correct, because guessing would let a caller conclude a
            // capability is held when it is not.
            return u64::from_str_radix(hex, 16).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("CapEff value {hex:?} is not hex: {e}"),
                )
            });
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no CapEff line in /proc/self/status",
    ))
}

/// `kernel.unprivileged_bpf_disabled`: when 2, an unprivileged process cannot
/// load BPF programs at all, regardless of what its capability mask says.
#[cfg(target_os = "linux")]
fn unprivileged_bpf() -> Check {
    const PATH: &str = "/proc/sys/kernel/unprivileged_bpf_disabled";
    match std::fs::read_to_string(PATH) {
        Ok(v) => {
            let trimmed = v.trim();
            match trimmed.parse::<u32>() {
                Ok(0) => Check::ok(
                    "unprivileged_bpf",
                    "unprivileged BPF loading is permitted by sysctl".to_string(),
                ),
                Ok(n) => Check::no(
                    "unprivileged_bpf",
                    format!("kernel.unprivileged_bpf_disabled = {n}; unprivileged loading is blocked"),
                ),
                Err(e) => Check::unknown(
                    "unprivileged_bpf",
                    format!("{PATH} held {trimmed:?}, not a number: {e}"),
                ),
            }
        }
        Err(e) => Check::unknown(
            "unprivileged_bpf",
            format!("could not read {PATH}: {e}"),
        ),
    }
}

/// BTF is what CO-RE relocation reads; without it a program compiled against
/// local headers may load but bind to the wrong offsets.
#[cfg(target_os = "linux")]
fn btf_present() -> Check {
    const PATH: &str = "/sys/kernel/btf/vmlinux";
    match std::fs::metadata(PATH) {
        Ok(m) => Check::ok(
            "btf",
            format!("{PATH} present ({} bytes)", m.len()),
        ),
        Err(e) => Check::no("btf", format!("{PATH} absent: {e}; CO-RE relocation is unavailable")),
    }
}

/// Locked-memory limit, which bounds BPF map sizes on kernels before 5.11.
#[cfg(target_os = "linux")]
fn memlock() -> Check {
    const PATH: &str = "/proc/self/limits";
    let status = match std::fs::read_to_string(PATH) {
        Ok(s) => s,
        Err(e) => {
            return Check::unknown("memlock", format!("could not read {PATH}: {e}"));
        }
    };
    for line in status.lines() {
        if line.starts_with("Max locked memory") {
            // The limit is in the second-to-last column, in bytes.
            let cols: Vec<&str> = line.split_whitespace().collect();
            return match cols.get(cols.len().wrapping_sub(2)).copied() {
                Some(v) => Check::ok("memlock", format!("Max locked memory = {v}")),
                None => Check::unknown("memlock", format!("could not parse limit line: {line}")),
            };
        }
    }
    Check::unknown("memlock", format!("no 'Max locked memory' line in {PATH}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn available_requires_every_check_to_be_satisfied() {
        let yes = Report {
            checks: vec![Check::ok("a", String::new()), Check::ok("b", String::new())],
        };
        assert!(yes.available());
        assert_eq!(yes.blockers().count(), 0);

        let no = Report {
            checks: vec![Check::ok("a", String::new()), Check::no("b", "nope".to_string())],
        };
        assert!(!no.available());
        assert_eq!(no.blockers().count(), 1);
    }

    #[test]
    fn indeterminate_is_not_available() {
        // "We could not look" must never read as "it is there". An agent that
        // concluded observation was available from a failed probe would have an
        // audit log with a silent hole in it.
        let r = Report { checks: vec![Check::unknown("a", "permission denied".to_string())] };
        assert!(!r.available());
        assert!(r.summary().contains("permission denied"));
    }

    #[test]
    fn summary_names_every_blocker() {
        let r = Report {
            checks: vec![
                Check::no("one", "first problem".to_string()),
                Check::no("two", "second problem".to_string()),
            ],
        };
        let s = r.summary();
        assert!(s.contains("one: first problem"), "{s}");
        assert!(s.contains("two: second problem"), "{s}");
    }

    #[test]
    fn probe_runs_without_panicking_on_this_platform() {
        let r = probe();
        // On a non-Linux host the answer must be a refusal with a reason, not
        // a bare error and not a panic.
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!r.available());
            assert!(r.summary().contains("platform"));
        }
        #[cfg(target_os = "linux")]
        {
            assert!(!r.checks.is_empty());
            let _ = r.summary();
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_checks_read_real_proc_entries() {
        // Exercises the readers against the running kernel. The assertions are
        // about shape rather than values, because the values depend on how the
        // test process was started.
        let checks = checks_linux();
        assert!(checks.iter().any(|c| c.id == "cap_bpf"));
        assert!(checks.iter().any(|c| c.id == "btf"));
        for c in &checks {
            assert!(!c.id.is_empty());
        }
    }
}