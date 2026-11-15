//! Random secrets and how they are stored.
//!
//! Every emailed or cookie-carried secret in this crate follows the same
//! rule: the value handed out is 32 bytes of OS randomness, and what lands in
//! the database is only its sha256. Reading the table therefore yields nothing
//! that can be replayed — the difference from the ancestor crate, where the
//! session cookie *was* the primary key.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// 32 random bytes, base64url without padding — 43 URL-safe characters, fine
/// in a cookie value, a query string, or a mail link.
pub fn secret() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Lowercase sha256 hex — 64 chars, matching the `varchar(64)` columns.
///
/// A plain hash rather than a password KDF is right here and wrong for
/// passwords: these inputs already carry 256 bits of entropy, so there is no
/// dictionary to slow an attacker down against.
pub fn hash(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Equality that takes the same time wherever the inputs differ — for
/// comparing a presented shared secret (`CLIENT_IP_KEY`). Both sides are
/// hashed first, so the length of the real one does not leak either.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (Sha256::digest(a), Sha256::digest(b));
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Six digits, uniformly drawn — the type-it-in confirmation code.
///
/// Rejection sampling rather than `% 1_000_000` so the low values are not
/// slightly more likely; the bias would be tiny but this costs nothing.
pub fn short_code() -> String {
    loop {
        let mut bytes = [0u8; 4];
        OsRng.fill_bytes(&mut bytes);
        let n = u32::from_le_bytes(bytes);
        // 4_294_000_000 is the largest multiple of 1_000_000 below u32::MAX.
        if n < 4_294_000_000 {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_64_hex_chars() {
        let h = hash("abc");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        // Known vector, so a future change of hash function is caught here.
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn secrets_differ_and_are_url_safe() {
        let a = secret();
        let b = secret();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn short_code_is_six_digits() {
        for _ in 0..64 {
            let c = short_code();
            assert_eq!(c.len(), 6);
            assert!(c.chars().all(|c| c.is_ascii_digit()));
        }
    }
}
