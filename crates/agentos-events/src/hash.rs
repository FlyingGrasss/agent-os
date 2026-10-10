//! SHA-256, transcribed from FIPS 180-4, used for the audit chain.
//!
//! ## Why this is a local copy and not a dependency
//!
//! `agentos-types` already contains a SHA-256 for binding confirmations, but it
//! is `pub(crate)` there and this crate may not edit that file. The workspace
//! also has a standing rule of zero new dependencies, so the algorithm is
//! transcribed here instead of pulling in a crate.
//!
//! ## What this does and does not buy
//!
//! The chain hash is *keyless*: the input is `prev || record_bytes`, and
//! anyone who can read the log can recompute every link. SHA-256 therefore
//! gives preimage and second-preimage resistance against someone who can only
//! edit records they did not write, which is what catches accidental
//! corruption, an out-of-order splice, and a naive edit-and-hope. It does
//! **not** stop an attacker who can recompute the whole chain: that is a
//! keyed-MAC problem (`HMAC` over the same construction, keyed by a secret
//! held outside the sandbox), and is out of scope here.
//!
//! The tests below check this against the published FIPS 180-4 vectors. If they
//! fail, the implementation is not SHA-256 and the chain digests would not
//! match any other implementation, so a verifier and an independent auditor
//! would disagree about whether a log was tampered with.

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A 32-byte digest. Distinct from any digest type elsewhere in the workspace
/// so that a value cannot be passed from one domain to the other by accident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct Digest(pub [u8; 32]);

/// Incremental hashing so a chain link can be fed `prev` and the record bytes
/// without concatenating them into a temporary buffer.
#[derive(Clone)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self { state: H0, block: [0u8; 64], block_len: 0, total_len: 0 }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }
    }

    pub(crate) fn finish(mut self) -> [u8; 32] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.pad(&[0x80]);
        while self.block_len != 56 {
            self.pad(&[0x00]);
        }
        self.pad(&bit_len.to_be_bytes());

        debug_assert_eq!(self.block_len, 0);
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Padding must not disturb the length counter, so it bypasses `update`.
    fn pad(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (64 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                let block = self.block;
                self.compress(&block);
                self.block_len = 0;
            }
        }
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (acc, next) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *acc = acc.wrapping_add(next);
        }
    }
}

/// One-shot hash over a sequence of parts, domain-separated by a leading label.
///
/// The label is hashed as a distinct part rather than being concatenated into
/// the data so that "the record bytes" and "some other structure that happens
/// to have the same bytes" cannot collide by construction.
pub(crate) fn hash_parts(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&(parts.len() as u64).to_be_bytes());
    h.update(label);
    for p in parts {
        h.update(&(p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finish()
}

/// Compare digests without an early exit, so a mismatch does not leak how many
/// leading bytes matched. Timing here is not the main defence, but there is no
/// reason to make it a free oracle.
pub(crate) fn digests_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8; 32]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(data);
        h.finish()
    }

    #[test]
    fn matches_published_sha256_vectors() {
        // FIPS 180-4 / NIST CAVS. If this fails the chain digests are not
        // SHA-256, and an auditor with a different implementation would reject
        // a log that we accepted.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn incremental_updates_match_one_shot_across_block_boundaries() {
        // Lengths around the padding boundaries are where a hand-written
        // implementation goes wrong.
        for n in [0usize, 1, 54, 55, 56, 63, 64, 65, 119, 120, 121, 200] {
            let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let one_shot = sha256(&data);

            let mut h = Sha256::new();
            for chunk in data.chunks(7) {
                h.update(chunk);
            }
            assert_eq!(h.finish(), one_shot, "digest mismatch at length {n}");
        }
    }

    #[test]
    fn part_boundaries_are_unambiguous() {
        // Without explicit length framing, ("ab","c") and ("a","bc") would
        // hash identically. If they collide here, a record could be resegmented
        // without changing its digest.
        assert_ne!(
            hash_parts(b"test", &[b"ab", b"c"]),
            hash_parts(b"test", &[b"a", b"bc"])
        );
    }

    #[test]
    fn labels_separate_domains() {
        assert_ne!(hash_parts(b"chain-link", &[b"x"]), hash_parts(b"other", &[b"x"]));
    }

    #[test]
    fn digests_equal_is_value_equality() {
        let a = sha256(b"x");
        let mut b = a;
        assert!(digests_equal(&a, &b));
        b[31] ^= 1;
        assert!(!digests_equal(&a, &b));
        let mut c = a;
        c[0] ^= 1;
        assert!(!digests_equal(&a, &c));
    }
}