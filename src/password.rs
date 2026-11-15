//! Password hashing and the policy around it.
//!
//! argon2id at the crate defaults (which track OWASP guidance), never SHA-1 -
//! see DESIGN.md section 1 for what older account code did instead.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use std::sync::OnceLock;

/// Hard bounds, not composition rules. NIST SP 800-63B advises against
/// "must contain a symbol" style requirements; length is the property that
/// matters. The upper bound exists because argon2 cost grows with input
/// length, so an unbounded field is a free denial-of-service.
pub const MIN_LEN: usize = 8;
pub const MAX_LEN: usize = 256;

/// Why a candidate password was rejected. Shown to the user as-is — these are
/// the one class of auth message that *should* be specific, since being vague
/// about a rejected new password only makes it unguessable to its own owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    TooShort,
    TooLong,
    SameAsEmail,
}

impl PolicyError {
    /// The key of its message in `locales/*.yml`
    pub(crate) fn key(self) -> &'static str {
        match self {
            PolicyError::TooShort => "err-password-short",
            PolicyError::TooLong => "err-password-long",
            PolicyError::SameAsEmail => "err-password-email",
        }
    }

    /// The API's answer for it: its code and its text in the request's language
    pub(crate) fn body(self) -> serde_json::Value {
        let (min, max) = (MIN_LEN.to_string(), MAX_LEN.to_string());
        crate::i18n::error_body(self.key(), &[("min", &min), ("max", &max)])
    }

    /// Its code, `SO-Ennn`: the same whatever the language of the text
    pub fn code(self) -> String {
        self.body()["code"].as_str().unwrap_or_default().to_string()
    }

    /// Its text in the language of the request (English outside one), without the code
    pub fn message(self) -> String {
        self.body()["error"].as_str().unwrap_or_default().to_string()
    }
}

pub fn check_policy(password: &str, email: &str) -> Result<(), PolicyError> {
    if password.len() < MIN_LEN {
        return Err(PolicyError::TooShort);
    }
    if password.len() > MAX_LEN {
        return Err(PolicyError::TooLong);
    }
    if password.trim().eq_ignore_ascii_case(email.trim()) {
        return Err(PolicyError::SameAsEmail);
    }
    Ok(())
}

pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash password: {e}"))?;
    Ok(hash.to_string())
}

pub fn verify(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A real hash that nothing is ever checked against, computed once per
/// process. `login` verifies against this when no user row is found, so an
/// unregistered address does not answer measurably faster than a wrong
/// password on a real account — the timing half of the enumeration guard that
/// the identical `401` body covers on the content side.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash("not-a-real-password-timing-decoy").expect("dummy hash"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let h = hash("correct horse battery staple").unwrap();
        assert!(verify("correct horse battery staple", &h));
        assert!(!verify("Correct horse battery staple", &h));
    }

    #[test]
    fn hash_is_salted() {
        assert_ne!(hash("same").unwrap(), hash("same").unwrap());
    }

    #[test]
    fn garbage_hash_never_verifies() {
        assert!(!verify("anything", "not-a-phc-string"));
        assert!(!verify("anything", ""));
    }

    #[test]
    fn policy() {
        assert_eq!(check_policy("short", "a@b.c"), Err(PolicyError::TooShort));
        assert_eq!(
            check_policy(&"x".repeat(257), "a@b.c"),
            Err(PolicyError::TooLong)
        );
        // Length is checked first, so the same-as-email case needs an address
        // that clears the minimum on its own.
        assert_eq!(
            check_policy("Owner@Example.com", "owner@example.com"),
            Err(PolicyError::SameAsEmail)
        );
        assert!(check_policy("long-enough-password", "a@b.com").is_ok());
    }
}
