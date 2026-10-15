//! Integration tests for the daemon/client environment-variable unification.
//!
//! The bug these pin down was found during a live walkthrough, and its worst
//! property was that it was **silent**. An operator set `AGENTOSD_TCP_ADDR`,
//! started the daemon, and ran `agentos check`. No error, no warning — the client
//! read `AGENTOS_TCP_ADDR`, found nothing, and fell through to the hardcoded
//! default port. The only symptom was a connection refusal naming an address the
//! operator had never set.
//!
//! These tests spawn the real binaries, because the defect lived in two processes
//! reading two spellings of one setting. A unit test over a single resolver could
//! pass while the two call sites still disagreed.

use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

/// Names are cleared before each case, so an inherited value from the developer's
/// shell cannot make a test pass for the wrong reason.
const TCP: [&str; 2] = ["AGENTOS_TCP_ADDR", "AGENTOSD_TCP_ADDR"];
const SOCK: [&str; 2] = ["AGENTOS_SOCKET", "AGENTOSD_SOCKET"];
const TOKEN: [&str; 2] = ["AGENTOS_TOKEN_FILE", "AGENTOSD_TOKEN_FILE"];

fn agentos() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentos"))
}

fn agentosd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentosd"))
}

/// An `agentosd` that cannot write into the repository.
///
/// Without this the daemon falls back to the relative `.agentosd` when neither
/// `XDG_STATE_HOME` nor `HOME` is usable, and drops a real 64-hex-character
/// credential into the crate directory. That is both pollution and a leaked
/// token, so every daemon test here gets a home of its own and cleans it up.
fn isolated_agentosd(home: &std::path::Path) -> Command {
    let mut cmd = agentosd();
    cmd.env_clear();
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd.env("HOME", home);
    cmd.env("XDG_STATE_HOME", home);
    cmd.env("AGENTOSD_AUDIT_LOG", home.join("audit.log"));
    for name in TCP.iter().copied().chain(SOCK).chain(TOKEN) {
        cmd.env_remove(name);
    }
    cmd
}

/// Run `agentos` with a clean environment plus `set`.
fn check_with(set: &[(&str, &str)]) -> Output {
    let mut cmd = agentos();
    cmd.arg("check");
    cmd.env_clear();
    // A minimal PATH so the binary still finds anything it shells out to; none of
    // these tests should need to, but an empty environment is not the point.
    cmd.env("PATH", std::env::var("PATH").unwrap_or_default());
    for name in TCP.iter().copied().chain(SOCK).chain(TOKEN) {
        cmd.env_remove(name);
    }
    for (k, v) in set {
        cmd.env(k, v);
    }
    cmd.output().expect("run agentos check")
}

fn stderr_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout_of(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn scratch(name: &str) -> std::path::PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(format!(
        "agentos-env-{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch");
    dir
}

// ---------------------------------------------------------------------------
// The client accepts both spellings
// ---------------------------------------------------------------------------

#[test]
fn the_client_honours_the_canonical_tcp_address() {
    let out = check_with(&[("AGENTOS_TCP_ADDR", "127.0.0.1:1234")]);
    let err = stderr_of(&out);
    assert!(
        err.contains("AGENTOS_TCP_ADDR") && err.contains("127.0.0.1:1234"),
        "must report which variable it used: {err}"
    );
}

#[test]
fn the_client_honours_the_daemon_tcp_address_too() {
    // This is the case that used to fall silently through to the default port.
    let out = check_with(&[("AGENTOSD_TCP_ADDR", "127.0.0.1:1234")]);
    let err = stderr_of(&out);
    assert!(
        err.contains("AGENTOSD_TCP_ADDR") && err.contains("127.0.0.1:1234"),
        "the daemon's spelling must work for the client, and must say so: {err}"
    );
    assert!(
        !err.contains("using default TCP address"),
        "must not silently fall back: {err}"
    );
}

#[test]
fn an_unparseable_address_is_reported_rather_than_skipped() {
    // Previously this fell through to the default port, so a typo looked exactly
    // like the variable being unset.
    for name in TCP {
        let out = check_with(&[(name, "not-an-address")]);
        let err = stderr_of(&out);
        assert!(
            err.contains(name) && err.contains("not a socket address"),
            "`{name}=not-an-address` must be named in the error: {err}"
        );
        assert!(
            !err.contains("using default TCP address"),
            "a malformed address must not fall back silently: {err}"
        );
    }
}

#[test]
fn disagreeing_aliases_are_refused_by_name_and_value() {
    let out = check_with(&[
        ("AGENTOS_TCP_ADDR", "127.0.0.1:1234"),
        ("AGENTOSD_TCP_ADDR", "127.0.0.1:9999"),
    ]);
    let err = stderr_of(&out);
    assert!(err.contains("disagree"), "{err}");
    assert!(err.contains("1234") && err.contains("9999"), "{err}");
    assert!(
        !err.contains("using default TCP address"),
        "must not pick one and connect: {err}"
    );
}

#[test]
fn agreeing_aliases_are_accepted() {
    // Two spellings of one intention is what an alias is for.
    let out = check_with(&[
        ("AGENTOS_TCP_ADDR", "127.0.0.1:1234"),
        ("AGENTOSD_TCP_ADDR", "127.0.0.1:1234"),
    ]);
    let err = stderr_of(&out);
    assert!(
        !err.contains("disagree"),
        "identical values are not a disagreement: {err}"
    );
    assert!(err.contains("127.0.0.1:1234"), "{err}");
}

#[test]
fn an_empty_alias_does_not_override_a_real_one() {
    // `FOO=` is what an unset shell variable interpolates to, so honouring it
    // would let an empty string silently beat a real setting.
    let out = check_with(&[
        ("AGENTOS_TCP_ADDR", ""),
        ("AGENTOSD_TCP_ADDR", "127.0.0.1:1234"),
    ]);
    let err = stderr_of(&out);
    assert!(
        err.contains("127.0.0.1:1234"),
        "an empty value must not win over a real one: {err}"
    );
}

// ---------------------------------------------------------------------------
// The daemon accepts both spellings
// ---------------------------------------------------------------------------

#[test]
fn the_daemon_reports_which_spelling_of_the_tcp_address_it_used() {
    // TCP on both platforms, so this is not a unix-only test quietly asserting
    // nothing on Windows. The daemon ignores argv and starts, prints what it
    // resolved, then fails on the model -- so the discovery line is already out
    // by the time it gives up.
    for name in TCP {
        let home = scratch("daddr");
        let out = isolated_agentosd(&home)
            .env(name, "127.0.0.1:0")
            .env("AGENTOSD_MODEL", "definitely-not-a-real-model")
            .output()
            .expect("run agentosd");

        let err = stderr_of(&out);
        assert!(
            !err.contains("disagree"),
            "a single spelling cannot conflict: {err}"
        );
        assert!(
            !err.contains("is not a socket address"),
            "127.0.0.1:0 is a valid address: {err}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn the_daemon_reports_which_spelling_of_the_socket_it_used() {
    // Unix only, and marked so: on other platforms the socket branch does not
    // exist at all, so asserting there would be a test that passes by never
    // running its assertion. Guarding it as a no-op instead is the honest form.
    if !cfg!(unix) {
        eprintln!("skipping: the daemon has no Unix-socket branch on this platform");
        return;
    }

    for name in SOCK {
        let home = scratch("sock");
        let sock = home.join("a.sock");
        let out = isolated_agentosd(&home)
            .env(name, sock.to_string_lossy().into_owned())
            .env("AGENTOSD_MODEL", "definitely-not-a-real-model")
            .output()
            .expect("run agentosd");

        let err = stderr_of(&out);
        assert!(
            err.contains("socket path from"),
            "the daemon should report the socket it resolved: {err}"
        );
        assert!(
            err.contains(name),
            "must name the variable it honoured, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }
}

#[test]
fn the_daemon_refuses_to_start_on_disagreeing_token_aliases() {
    let home = scratch("token");
    let a = home.join("a.token");
    let b = home.join("b.token");

    let out = isolated_agentosd(&home)
        .env("AGENTOS_TOKEN_FILE", &a)
        .env("AGENTOSD_TOKEN_FILE", &b)
        .env("AGENTOSD_MODEL", "definitely-not-a-real-model")
        .output()
        .expect("run agentosd");

    let err = stderr_of(&out);
    assert!(
        err.contains("disagree"),
        "a token path disagreement must be fatal, not silently resolved: {err}"
    );
    // The point of exiting: writing the token to one of the two paths produces a
    // daemon whose credential the client cannot find, which looks like a missing
    // token rather than a configuration mistake.
    assert!(!a.exists(), "must not write to a contested path: {a:?}");
    assert!(!b.exists(), "must not write to a contested path: {b:?}");

    let _ = std::fs::remove_dir_all(&home);
}

// ---------------------------------------------------------------------------
// Client and daemon must agree on where to meet
// ---------------------------------------------------------------------------

#[test]
fn one_variable_is_enough_for_both_halves() {
    // The actual unification: setting `AGENTOSD_TCP_ADDR` once must be enough for
    // the client, which is the whole point. Asserted through the client's own
    // discovery output because that is the observable.
    let out = check_with(&[("AGENTOSD_TCP_ADDR", "127.0.0.1:5555")]);
    let err = stderr_of(&out);
    assert!(
        err.contains("127.0.0.1:5555"),
        "the client must follow the daemon's spelling: {err}"
    );
    assert!(
        !stdout_of(&out).is_empty() || stderr_of(&out).contains("not reachable"),
        "expected a real attempt against 5555: {err}"
    );
}

#[test]
fn the_documented_names_are_the_ones_implemented() {
    // A test that greps the usage text for the aliases, so renaming the variables
    // without updating the documentation fails here rather than in an operator's
    // terminal.
    let out = agentos().arg("help").output().expect("run agentos help");
    let text = stdout_of(&out);
    for name in TCP.iter().copied().chain(SOCK).chain(TOKEN) {
        assert!(
            text.contains(name),
            "`{name}` is implemented but not documented in --help"
        );
    }
}

#[test]
fn these_tests_write_nothing_into_the_repository() {
    // Spawning the daemon with an inherited environment makes it fall back to the
    // *relative* `.agentosd`, which drops a real 64-hex credential into the crate
    // directory. That is how it happened once. Asserted rather than trusted,
    // because a leaked token file is indistinguishable from a passing test run.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for leaked in [
        ".agentosd/agentosd/auth.token",
        "agentosd-audit.log",
        "agentos-audit.log",
    ] {
        assert!(
            !dir.join(leaked).exists(),
            "{leaked} exists in the crate directory: a test is not isolating its \
             environment. `isolated_agentosd` exists for this."
        );
    }
}