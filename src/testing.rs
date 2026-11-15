//! Signers for other crates' tests, behind the `test-support` feature: what
//! a mock IdP needs to answer a relying party built on this crate. The keys
//! are test keys, made with `openssl` on the machine that runs the tests the
//! first time one is asked for (`fixture_keys.rs`) and kept there, out of the
//! repository — enable the feature from a `[dev-dependencies]` entry only,
//! never for a build that ships.

/// ES256 id_tokens and the JWKS that verifies them (a fixed P-256 key).
pub use crate::jwt::test_keys as id_token;

/// A signed SAML Response from the tests' signing key (`fixture_keys.rs`).
#[cfg(feature = "saml")]
pub mod saml {
    /// The certificate a connection trusts to accept [`sign_response`]'s output:
    /// the one of the key this machine signs with.
    pub fn idp_cert_pem() -> &'static str {
        &crate::fixture_keys::signer().cert_pem
    }

    /// Signs the `Assertion` inside `unsigned` (enveloped, exclusive C14N,
    /// RSA-SHA256) and puts the `ds:Signature` where `<!--SIG-->` stands —
    /// right after the assertion's `Issuer`, where the schema wants it.
    ///
    /// Uses this crate's own C14N, which `saml::tests` checks against
    /// libxml2 and signxml-signed fixtures; a test built on this is about
    /// the wiring around the verifier, not the verifier.
    pub fn sign_response(unsigned: &str) -> String {
        crate::saml::sign::sign_enveloped(unsigned, "Assertion", &crate::fixture_keys::signer().key_pem, None)
    }
}
