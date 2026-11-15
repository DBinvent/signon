//! Where sign-in provider configuration comes from at request time, and the
//! small domain helpers SSO code on both sides of a federation needs.
//!
//! Until 2026-10 the configured OAuth providers were a `Vec` read once from
//! the environment at startup. That still is the default — a site that only
//! sets `OAUTH_<PROVIDER>_*` sees no difference — but the list now lives in a
//! [`SsoRegistry`] a service can *replace* while running.
//!
//! Customer SSO connections are not here: a product that has them runs them in
//! a separate SSO service, which uses this crate's
//! protocol libraries (`oauth`, `oidc`, `saml`) and hands its sites a
//! verified identity through feature `sso-broker` (`broker.rs`).
//!
//! A snapshot is replaced whole, never patched: a request sees one coherent
//! configuration from start to finish.

use std::sync::{Arc, RwLock};

use crate::oauth::Configured;

/// One coherent view of the social providers this site signs in with.
#[derive(Clone, Default)]
pub struct SsoSnapshot {
    pub providers: Vec<Configured>,
    /// Opaque, for the feeder's own change detection (an ETag, a hash).
    pub version: String,
}

impl SsoSnapshot {
    pub fn provider(&self, key: &str) -> Option<&Configured> {
        self.providers.iter().find(|c| c.provider.key == key)
    }
}

/// The live configuration. Cheap to read: a read lock held only long enough
/// to clone an `Arc`.
pub struct SsoRegistry {
    current: RwLock<Arc<SsoSnapshot>>,
}

impl SsoRegistry {
    pub fn new(snapshot: SsoSnapshot) -> Self {
        Self {
            current: RwLock::new(Arc::new(snapshot)),
        }
    }

    pub fn current(&self) -> Arc<SsoSnapshot> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Swaps in a new configuration. Requests already in flight finish on the
    /// snapshot they started with.
    pub fn replace(&self, snapshot: SsoSnapshot) {
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(snapshot);
    }
}

/// A customer-connection slug: lowercase letters, digits and single hyphens,
/// 3–40 characters. It is a URL path segment a customer copies into their
/// IdP, so it has to survive being typed, pasted and compared byte for byte.
pub fn valid_slug(slug: &str) -> bool {
    (3..=40).contains(&slug.len())
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && !slug.contains("--")
}

/// The part after the last `@`, lowercased by the caller's normalisation.
pub fn domain_of(email: &str) -> Option<&str> {
    let (_, domain) = email.rsplit_once('@')?;
    (!domain.is_empty()).then_some(domain)
}

/// Mailbox providers anyone can get an address at. Claiming one as an SSO
/// domain would hand the claimant every user of that provider, so these are
/// refused outright, verification or not. Not exhaustive — the domain proof
/// is what actually protects a domain — but it closes the obvious mistakes
/// before they reach a DNS check.
pub const PUBLIC_MAILBOX_DOMAINS: &[&str] = &[
    "aol.com",
    "fastmail.com",
    "gmail.com",
    "gmx.com",
    "gmx.de",
    "googlemail.com",
    "hey.com",
    "hotmail.com",
    "icloud.com",
    "live.com",
    "mac.com",
    "mail.com",
    "mail.ru",
    "me.com",
    "msn.com",
    "outlook.com",
    "privaterelay.appleid.com",
    "proton.me",
    "protonmail.com",
    "qq.com",
    "tutanota.com",
    "web.de",
    "yahoo.com",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
];

pub fn is_public_mailbox_domain(domain: &str) -> bool {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    PUBLIC_MAILBOX_DOMAINS.contains(&domain.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_mailbox_domains_are_recognised_case_insensitively() {
        assert!(is_public_mailbox_domain("Gmail.com"));
        assert!(is_public_mailbox_domain("gmail.com."));
        assert!(!is_public_mailbox_domain("acme.com"));
    }

    #[test]
    fn slugs_are_url_safe() {
        assert!(valid_slug("acme"));
        assert!(valid_slug("acme-corp-2"));
        for bad in ["ab", "Acme", "acme_corp", "-acme", "acme-", "ac--me", "a/b", "acme.com"] {
            assert!(!valid_slug(bad), "{bad}");
        }
    }

    #[test]
    fn domain_of_takes_the_last_at() {
        assert_eq!(domain_of("a@b.com"), Some("b.com"));
        assert_eq!(domain_of("\"a@x\"@b.com"), Some("b.com"));
        assert_eq!(domain_of("a@"), None);
        assert_eq!(domain_of("nope"), None);
    }
}
