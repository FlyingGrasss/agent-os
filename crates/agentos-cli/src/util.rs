//! Shared utilities for the CLI.

use uuid::Uuid;
use agentos_types::UserId;

/// One user, fixed.
///
/// The CLI runs as one person on one machine. Deriving a real identity from the
/// OS would be the right thing for a multi-user daemon and is out of scope here;
/// what matters is that it is *deterministic within a run*, so the audit trail's
/// origin column means something.
pub fn user_id() -> UserId {
    let mut b = [0u8; 16];
    b[15] = 0x01;
    UserId(Uuid::from_bytes(b))
}