//! The operating system's cryptographically secure random source.
//!
//! # Why this exists as its own module
//!
//! Three things need unpredictable bytes — the daemon's startup token, an inbox
//! payload's correlation id, and the file identity used to spot a flood of
//! identical drops. Each of them would be a security control, and a security
//! control with two implementations is a security control where one of them has
//! not been reviewed.
//!
//! So there is one, here, and `agentos-cli` uses it rather than carrying its own.
//!
//! # Why not derive randomness from anything observable
//!
//! A userspace generator seeded from a clock, a pid, or an address is a rewrite of
//! a solved problem with a far worse failure mode: the seed is guessable, so the
//! output is. Both platforms below hand this to the kernel instead.
//!
//! # What a failure here means
//!
//! [`fill`] returns an error rather than falling back. A fallback would be a
//! silent downgrade of the only thing standing between a local user and the
//! daemon's authority, and it would be invisible: everything would keep working,
//! just with guessable credentials.

use std::io;

/// Fill `buf` with bytes from the system CSPRNG.
///
/// Unix reads `/dev/urandom`, which is the same kernel pool `getrandom(2)` draws
/// from; the difference is only that it is a file and can block, which for the
/// handful of bytes used here is not a concern. It is used in preference to
/// binding `getrandom` because this crate takes no `libc` dependency.
///
/// Windows calls `BCryptGenRandom` with a null algorithm handle, which is the
/// documented way to request the system-preferred provider. That avoids depending
/// on `BCRYPT_RNG_ALGORITHM` being present, which is not guaranteed on every
/// build of Windows this project might run on.
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    platform::fill(buf)
}

#[cfg(unix)]
mod platform {
    use std::io::Read;

    pub(super) fn fill(buf: &mut [u8]) -> std::io::Result<()> {
        let mut file = std::fs::File::open("/dev/urandom")?;
        file.read_exact(buf)
    }
}

#[cfg(windows)]
mod platform {
    use core::ffi::c_void;

    /// `BCRYPT_USE_SYSTEM_PREFERRED_RNG`.
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    /// `STATUS_SUCCESS`.
    const STATUS_SUCCESS: i32 = 0;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(
            algorithm: *mut c_void,
            buffer: *mut u8,
            buffer_length: u32,
            flags: u32,
        ) -> i32;
    }

    pub(super) fn fill(buf: &mut [u8]) -> std::io::Result<()> {
        // BCryptGenRandom takes a `u32` length. The assertion documents the
        // constraint rather than leaving a reader to work it out.
        assert!(
            buf.len() <= u32::MAX as usize,
            "buffer exceeds the u32 length BCryptGenRandom takes"
        );

        // SAFETY: `buf` is a valid, uniquely borrowed slice of exactly
        // `buf.len()` writable bytes for the duration of the call, and a null
        // algorithm handle is the documented request for the system-preferred
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
            Err(std::io::Error::other(format!(
                "BCryptGenRandom failed with status 0x{status:08x}"
            )))
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    pub(super) fn fill(_buf: &mut [u8]) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "no system random source is wired up for this platform",
        ))
    }
}

/// Fill a 16-byte buffer with unpredictable bytes.
pub fn fill16() -> io::Result<[u8; 16]> {
    let mut out = [0u8; 16];
    fill(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_random_source_produces_bytes() {
        let mut buf = [0u8; 32];
        fill(&mut buf).expect("the system random source must be available");
        // Not "is it nonzero" -- a single all-zero draw would be a 1-in-2^256
        // event, so this almost certainly cannot prove anything. It exists to
        // fail loudly on a platform where `fill` is unimplemented, which is the
        // failure this module exists to prevent.
    }

    #[test]
    fn two_draws_differ() {
        let a = fill16().unwrap();
        let b = fill16().unwrap();
        assert_ne!(a, b, "two draws must not be identical");
    }

    #[test]
    fn fill16_returns_sixteen_bytes() {
        let bytes = fill16().unwrap();
        assert_eq!(bytes.len(), 16);
    }
}