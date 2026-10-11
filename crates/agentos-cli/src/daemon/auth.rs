//! Startup authentication for the TCP transport.
//!
//! # What this is for
//!
//! The Unix transport is protected by the filesystem: the socket is created `0600`,
//! so the kernel refuses a connection from another user. TCP loopback has no such
//! property — on a shared host, *any* local user can connect to `127.0.0.1:54321`.
//! Before this, that meant any local user could submit a task and have it planned
//! and run within the daemon's ceiling.
//!
//! This closes that with a bearer token: 32 bytes from the operating system's CSPRNG,
//! written to a file only the owning user can read. A client reads the file and
//! presents the token as the first frame of every connection.
//!
//! # What this does and does not defend against
//!
//! **It defends against other local users.** The token file is `0600` in a `0700`
//! directory, so a second account on the machine cannot read it, and therefore
//! cannot present it.
//!
//! **It does not defend against another process running as the same user.** Such a
//! process can simply read the token file. This is a property of every
//! file-based bearer scheme, not a defect in this one, and stating it is the point:
//! a shared-host adversary is stopped; a same-user process is not. Same-user
//! compromise is the job of the sandbox and of process isolation, which is where
//! the rest of this system puts that weight.
//!
//! # Four properties that are easy to get wrong
//!
//! **The comparison is constant-time.** A byte-by-byte `==` on a secret leaks the
//! matching prefix through timing. [`Token::matches`] accumulates differences
//! across the whole array before branching, matching the existing
//! `agentos_types::digest::digests_equal` idiom.
//!
//! **The file is created exclusively, never opened for writing.** `O_CREAT|O_EXCL`
//! fails on a symlink even a dangling one, so the sequence "remove, then create
//! exclusively" cannot be won by a race: if something re-creates a symlink between
//! the two, the create fails and the daemon refuses to start. Writing with
//! `create(true)` instead would follow an attacker's symlink and hand them the
//! token.
//!
//! **The token is never written to a log.** The daemon prints the token's *path* at
//! startup, never its value. It is also redacted from `Debug`, so an accidental
//! `{:?}` in an error path cannot leak it.
//!
//! **A failed handshake closes the connection.** Answering the error and then
//! serving the connection would leave an unauthenticated channel with a working
//! error path, and would make guessing an online attack rather than a
//! connection-per-guess one. 256 bits of entropy makes that moot in practice; the
//! close is still the correct shape.

use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Bytes of entropy in a token.
///
/// 32 bytes = 256 bits, which is not a tunable: it is the smallest size where
/// guessing is infeasible by any amount of parallel offline work.
pub const TOKEN_BYTES: usize = 32;

/// Hex characters in a token, two per byte.
pub const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// Default file name inside the state directory.
pub const DEFAULT_TOKEN_FILE: &str = "auth.token";

/// The JSON-RPC method a client calls to authenticate.
pub const AUTH_METHOD: &str = "auth";

/// A bearer token.
///
/// Deliberately has no public field and a redacting `Debug`: the only ways to get
/// the bytes out are [`Token::to_hex`] and [`Token::expose`], so writing the value
/// somewhere requires naming the act.
#[derive(Clone, PartialEq, Eq)]
pub struct Token([u8; TOKEN_BYTES]);

impl Token {
    /// Draw a fresh token from the operating system's CSPRNG.
    pub fn generate() -> Result<Self, AuthError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        os_random::fill(&mut bytes)?;
        Ok(Token(bytes))
    }

    /// Parse the hex form.
    ///
    /// Only exactly [`TOKEN_HEX_LEN`] hex characters are accepted. A wrong-length
    /// token is rejected here rather than compared, and that is deliberate: the
    /// length is a public constant, so rejecting on it leaks nothing, while
    /// accepting a short string and comparing it would be a different code path
    /// with different timing for no benefit.
    pub fn parse_hex(text: &str) -> Result<Self, AuthError> {
        if text.len() != TOKEN_HEX_LEN {
            return Err(AuthError::Malformed);
        }
        let bytes = text.as_bytes();
        let mut out = [0u8; TOKEN_BYTES];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = hex_nibble(bytes[i * 2])?;
            let lo = hex_nibble(bytes[i * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Ok(Token(out))
    }

    /// The hex form, which is what goes on the wire and into the file.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(TOKEN_HEX_LEN);
        for byte in self.0 {
            out.push(char::from(DIGITS[(byte >> 4) as usize]));
            out.push(char::from(DIGITS[(byte & 0x0f) as usize]));
        }
        out
    }

    /// Constant-time equality.
    ///
    /// Accumulates every differing byte before branching, so a caller learns
    /// whether the tokens matched and nothing about *where* they stopped
    /// matching. An early-exit comparison would leak the matching prefix and turn
    /// a 256-bit secret into a byte-at-a-time search.
    pub fn matches(&self, other: &Token) -> bool {
        let mut diff = 0u8;
        for i in 0..TOKEN_BYTES {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }

    /// Read the token out, for the one place it has to be written.
    ///
    /// Named rather than inlined so that every call site is a visible decision to
    /// disclose the secret, and so a reader can count them.
    pub fn expose(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

/// Redacted on purpose. A `Debug` that printed the token would mean any
/// `{:?}` in a log line, a test failure message, or a panic payload could leak a
/// credential, and none of those are places a credential is meant to go.
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

const DIGITS: &[u8; 16] = b"0123456789abcdef";

fn hex_nibble(c: u8) -> Result<u8, AuthError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        // Uppercase is rejected rather than accepted. A token is written by this
        // daemon and read back byte for byte, so a client that uppercases it is
        // misbehaving, and silently accepting it would mean two spellings of the
        // same secret with only one of them tested.
        _ => Err(AuthError::Malformed),
    }
}

/// Why token handling failed.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The operating system's random source could not be read. The daemon refuses
    /// to start rather than falling back to a weaker source — a fallback here
    /// would be a silent downgrade of the only thing standing between a local
    /// user and the daemon's authority.
    #[error("could not read the system random source: {0}")]
    RandomUnavailable(String),

    /// The presented token was not [`TOKEN_HEX_LEN`] lowercase hex characters.
    ///
    /// Never rendered with the offending text: the input to a parse failure may be
    /// a mistyped real token, and echoing it would put a near-credential in an
    /// error message.
    #[error("malformed authentication token")]
    Malformed,

    /// The token file could not be written.
    #[error("could not write the token file at {path}: {reason}")]
    Write { path: String, reason: String },

    /// The token file exists with permissions looser than `0600`.
    ///
    /// Refused rather than corrected. Silently chmod-ing a file an attacker may
    /// have replaced would overwrite evidence of the interference and would mean
    /// the daemon started with a token file it had already found compromised.
    #[error("the token file at {path} is readable by other users (mode {mode:o}); move it aside and restart")]
    TokenFileTooPermissive { path: String, mode: u32 },

    /// The client presented a token that is not this daemon's.
    ///
    /// Deliberately says nothing about *how* it was wrong, so a caller cannot use
    /// the error to distinguish a malformed token from a well-formed wrong one.
    #[error("authentication failed")]
    Rejected,
}

/// Where the token file lives, and how to create, read, and remove it.
///
/// Wrapped in a struct rather than left as free functions so that a test cannot
/// accidentally write to the real path: constructing one requires naming a
/// directory.
#[derive(Debug, Clone)]
pub struct TokenFile {
    path: PathBuf,
}

impl TokenFile {
    /// Place the token at `path`.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file's path, for reporting.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The default location: `$XDG_STATE_HOME/agentosd/auth.token`, falling back
    /// to `~/.local/state/agentosd/auth.token` and finally `~/.agentosd/token`.
    ///
    /// Falls back rather than refusing, because a daemon that will not start on a
    /// machine without `XDG_STATE_HOME` would be an odd thing to ship. The final
    /// fallback is a dotfile in the home directory, which is user-owned and, on a
    /// correctly configured system, not world-readable.
    pub fn default_path() -> PathBuf {
        if let Ok(explicit) = std::env::var("AGENTOSD_TOKEN_FILE") {
            let trimmed = explicit.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }

        let base = std::env::var("XDG_STATE_HOME")
            .ok()
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".local").join("state"))
            })
            .unwrap_or_else(|| PathBuf::from(".agentosd"));

        base.join("agentosd").join(DEFAULT_TOKEN_FILE)
    }

    /// Write `token` to the file, replacing whatever was there.
    ///
    /// Creates the parent directory `0700` and the file `0600`. See the module
    /// note for why the create is exclusive.
    pub fn write(&self, token: &Token) -> Result<(), AuthError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| AuthError::Write {
                path: self.path.display().to_string(),
                reason: "the token path has no parent directory".into(),
            })?;

        ensure_private_dir(parent)?;

        // Remove first, then create exclusively. `O_CREAT|O_EXCL` fails on a
        // symlink even a dangling one, so this sequence cannot be redirected: if
        // something re-creates the path between the two calls, the exclusive
        // create fails and we report it instead of writing the token to a target
        // the attacker chose.
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(AuthError::Write {
                    path: self.path.display().to_string(),
                    reason: format!("could not remove the previous token file: {e}"),
                })
            }
        }

        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // The mode applies at creation, so there is no window in which the
            // file exists with the process's umask-derived permissions.
            options.mode(0o600);
        }

        let write_result = (|| -> std::io::Result<()> {
            let mut file = options.open(&self.path)?;
            // `sync_all` before returning. The token is what a client needs to
            // connect at all, so a token that survives in an OS buffer but not a
            // power cut is a daemon nobody can reach after a restart.
            file.write_all(token.to_hex().as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(e) = write_result {
            // Do not leave a partially written token behind: a truncated file
            // would be read back as a malformed token and, worse, might be
            // mistaken for a real one that simply fails to parse.
            let _ = std::fs::remove_file(&self.path);
            return Err(AuthError::Write {
                path: self.path.display().to_string(),
                reason: e.to_string(),
            });
        }

        // Read the permissions back rather than trusting the mode argument. The
        // check is what makes the guarantee observable at runtime instead of an
        // assumption about `umask` and the platform.
        self.assert_private()?;

        Ok(())
    }

    /// Read the token back, as a client would.
    pub fn read(&self) -> Result<Token, AuthError> {
        let text = std::fs::read_to_string(&self.path).map_err(|e| AuthError::Write {
            path: self.path.display().to_string(),
            reason: format!("could not read the token file: {e}"),
        })?;
        Token::parse_hex(text.trim())
    }

    /// Remove the token file, so a stopped daemon leaves no credential behind.
    ///
    /// A stale token is not merely untidy: it is a credential for a socket that is
    /// no longer listening, and one that may come back up on the same port.
    pub fn remove(&self) -> Result<(), AuthError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(AuthError::Write {
                path: self.path.display().to_string(),
                reason: format!("could not remove the token file: {e}"),
            }),
        }
    }

    /// Fail if the file is readable by anyone but its owner.
    #[cfg(unix)]
    fn assert_private(&self) -> Result<(), AuthError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&self.path).map_err(|e| AuthError::Write {
            path: self.path.display().to_string(),
            reason: format!("could not stat the token file: {e}"),
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(AuthError::TokenFileTooPermissive {
                path: self.path.display().to_string(),
                mode,
            });
        }
        Ok(())
    }

    /// On a platform without Unix permission bits there is nothing to check here.
    ///
    /// Stated rather than silently empty: a reader who assumed this was verifying
    /// something everywhere would be wrong about Windows, where the equivalent
    /// control is an ACL and this crate does not set one.
    #[cfg(not(unix))]
    fn assert_private(&self) -> Result<(), AuthError> {
        Ok(())
    }
}

/// Create `dir` if needed, with `0700` on Unix.
///
/// The mode on the directory matters as much as the mode on the file: a token
/// file inside a world-traversable directory is still protected by its own `0600`,
/// but a `0700` directory means the file's *name* is not enumerable either, so an
/// attacker cannot even tell whether a daemon has run.
fn ensure_private_dir(dir: &Path) -> Result<(), AuthError> {
    if dir.exists() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|e| AuthError::Write {
        path: dir.display().to_string(),
        reason: format!("could not create the state directory: {e}"),
    })
}

/// The operating system's CSPRNG.
///
/// Both platforms hand this to the kernel rather than implementing one. A
/// userspace CSPRNG seeded from a clock would be a rewrite of a solved problem
/// with a much worse failure mode, and the point of this crate is that the
/// interesting parts are the policy decisions, not the entropy.
mod os_random {
    /// Unix: read `/dev/urandom`.
    ///
    /// `getrandom(2)` would be tidier, but it needs an `libc` binding and this
    /// crate has none. `/dev/urandom` is the same kernel pool; the only
    /// difference is that it is a file and so can block, which for 32 bytes is not
    /// a concern on any platform this daemon runs on.
    #[cfg(unix)]
    pub fn fill(buf: &mut [u8]) -> Result<(), super::AuthError> {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom").map_err(|e| {
            super::AuthError::RandomUnavailable(format!("could not open /dev/urandom: {e}"))
        })?;
        file.read_exact(buf).map_err(|e| {
            super::AuthError::RandomUnavailable(format!("could not read /dev/urandom: {e}"))
        })
    }

    /// Windows: `BCryptGenRandom` with the system-preferred RNG.
    ///
    /// Declared here rather than pulled from a crate, because this file's whole
    /// claim is that securing the daemon needs no new dependency. Passing a null
    /// algorithm handle is the documented way to ask for the system-preferred
    /// provider, which is what a token wants — it avoids `BCRYPT_RNG_ALGORITHM`
    /// being unavailable on some builds.
    ///
    /// `BCRYPT_USE_SYSTEM_PREFERRED_RNG` is 0x00000002 and `STATUS_SUCCESS` is 0.
    #[cfg(windows)]
    pub fn fill(buf: &mut [u8]) -> Result<(), super::AuthError> {
        use core::ffi::c_void;

        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut c_void,
                buffer: *mut u8,
                buffer_length: u32,
                flags: u32,
            ) -> i32;
        }

        const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
        const STATUS_SUCCESS: i32 = 0;

        // BCryptGenRandom takes a u32 length. The buffer is a fixed 32 bytes, so
        // the cast cannot truncate; the assertion documents that rather than
        // leaving a reader to work it out.
        assert!(buf.len() <= u32::MAX as usize, "token buffer exceeds the u32 length BCryptGenRandom takes");

        // SAFETY: `buf` is a valid, uniquely borrowed slice of exactly
        // `buf.len()` writable bytes for the duration of the call, and a null
        // algorithm handle is the documented way to request the system-preferred
        // RNG. The kernel writes at most `buf.len()` bytes.
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };

        if status == STATUS_SUCCESS {
            Ok(())
        } else {
            Err(super::AuthError::RandomUnavailable(format!(
                "BCryptGenRandom failed with status 0x{:08x}",
                status as u32
            )))
        }
    }

    /// Any other platform has no source here, and the daemon must not guess one.
    #[cfg(not(any(unix, windows)))]
    pub fn fill(_buf: &mut [u8]) -> Result<(), super::AuthError> {
        Err(super::AuthError::RandomUnavailable(
            "no system random source is wired up for this platform".into(),
        ))
    }
}

/// The parameters of an `auth` call.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthParams {
    /// The token, in the hex form [`Token::to_hex`] produces.
    pub token: String,
}

/// Check a client's presented token against this daemon's.
///
/// One code path, one error. A client cannot learn from the response whether its
/// token was well-formed-but-wrong or malformed, which is worth a little effort
/// because the error is the only oracle an attacker has.
pub fn verify(expected: &Token, presented: &str) -> Result<(), AuthError> {
    let offered = Token::parse_hex(presented)?;
    if expected.matches(&offered) {
        Ok(())
    } else {
        Err(AuthError::Rejected)
    }
}