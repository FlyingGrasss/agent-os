//! The `agentosd` binary.
//!
//! Everything of substance lives in the [`agentos_cli::daemon`] library, so that it
//! can be tested without starting a process and bound to a port. This file is the
//! entry point and holds nothing else -- the same division the `agentos` binary
//! uses, and for the same reason: a binary nobody can link against is not
//! something that can be verified.

fn main() -> std::process::ExitCode {
    agentos_cli::daemon::entry_point()
}