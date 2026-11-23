//! `SSO.md` SSO-18. The fixtures under `tests/fixtures/saml/` were signed by
//! `signxml` (an independent XML-DSig implementation over libxml2), with a
//! throwaway test key — see `idp_cert.pem`. The attack variants were derived
//! from the good ones after signing. That set is not pushed: where the
//! directory is missing, `fixture_gen.rs` makes the same documents with a new
//! key and this crate's own signer, and these tests read those.

use super::*;

const ACS: &str = "https://register.test/api/account/sso/acme/acs";
const ENTITY: &str = "https://register.test/api/account/sso/acme/metadata";
const REQUEST: &str = "_req1";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(super::fixture_gen::dir().join(name)).unwrap()
}

fn settings() -> SamlSettings {
    SamlSettings {
        idp_entity_id: "https://idp.acme.test".into(),
        sso_url: "https://idp.acme.test/sso/saml".into(),
        certificates: vec![certificate_der(&fixture("idp_cert.pem")).unwrap()],
    }
}

/// Inside every fixture's validity window (09:59–10:05).
fn now() -> DateTime<Utc> {
    "2026-10-04T10:01:00Z".parse().unwrap()
}

fn verify(name: &str) -> anyhow::Result<Assertion> {
    verify_at(name, now())
}

fn verify_at(name: &str, at: DateTime<Utc>) -> anyhow::Result<Assertion> {
    let b64 = STANDARD.encode(fixture(&format!("{name}.xml")));
    verify_response(
        &b64,
        &settings(),
        &Sp {
            entity_id: ENTITY,
            acs_url: ACS,
        },
        REQUEST,
        at,
    )
}

#[test]
fn sso18_a_signed_assertion_verifies() {
    let a = verify("signed_assertion").unwrap();
    assert_eq!(a.subject, "bob@acme.com");
    assert_eq!(a.email.as_deref(), Some("bob@acme.com"));
    assert_eq!(a.name.as_deref(), Some("Bob Builder"));
}

#[test]
fn sso18_a_signed_response_covering_the_assertion_verifies() {
    let a = verify("signed_response").unwrap();
    assert_eq!(a.email.as_deref(), Some("bob@acme.com"));
}

#[test]
fn sso18_email_comes_from_an_attribute_when_nameid_is_not_an_email() {
    let a = verify("persistent_nameid").unwrap();
    assert_eq!(a.subject, "a1b2c3");
    assert_eq!(a.email.as_deref(), Some("bob@acme.com"));
}

#[test]
fn sso18_every_attack_and_mismatch_is_refused() {
    for (name, why) in [
        ("unsigned", "no signature at all"),
        ("attacker_signed", "signed by a key that is not configured"),
        ("tampered_nameid", "NameID changed after signing"),
        ("sha1_method", "SHA-1 signature method"),
        ("wrong_audience", "Audience is another SP"),
        ("wrong_recipient", "Recipient is not our ACS"),
        ("wrong_request", "InResponseTo another request"),
        ("other_issuer", "Issuer is not the configured IdP"),
        ("xsw_hidden_original", "signature wrapping: signed original hidden, unsigned one in its place"),
        ("xsw_duplicate_id", "signature wrapping: forged assertion reusing the signed ID"),
        ("doctype", "DOCTYPE"),
        ("encrypted", "EncryptedAssertion"),
    ] {
        assert!(verify(name).is_err(), "{name} was accepted ({why})");
    }
}

#[test]
fn sso18_expiry_and_not_before_are_enforced_with_skew() {
    // Expired fixture: NotOnOrAfter 09:30.
    assert!(verify("expired").is_err());
    // Good fixture, but checked an hour after it lapsed.
    assert!(verify_at("signed_assertion", "2026-10-04T11:00:00Z".parse().unwrap()).is_err());
    // …and well before NotBefore (09:59).
    assert!(verify_at("signed_assertion", "2026-10-04T09:00:00Z".parse().unwrap()).is_err());
    // Within the two-minute skew either side is fine.
    assert!(verify_at("signed_assertion", "2026-10-04T09:58:00Z".parse().unwrap()).is_ok());
}

#[test]
fn sso18_a_comment_inside_nameid_cannot_truncate_the_address() {
    // The 2018 class of bug: a comment is invisible to the digest, and a
    // reader that took only the first text node would see bob@acme.com.
    let a = verify("comment_in_nameid").unwrap();
    assert_eq!(a.subject, "bob@acme.com.evil.test");
    assert_eq!(a.email.as_deref(), Some("bob@acme.com.evil.test"));
}

#[test]
fn a_response_for_another_request_id_is_refused_even_when_signed() {
    let b64 = STANDARD.encode(fixture("signed_assertion.xml"));
    let sp = Sp {
        entity_id: ENTITY,
        acs_url: ACS,
    };
    assert!(verify_response(&b64, &settings(), &sp, "_other", now()).is_err());
}

#[test]
fn idp_metadata_yields_entity_url_and_certificate() {
    let (entity, sso, certs) = parse_idp_metadata(&fixture("idp_metadata.xml")).unwrap();
    assert_eq!(entity, "https://idp.acme.test");
    assert_eq!(sso, "https://idp.acme.test/sso/saml");
    assert_eq!(certs, settings().certificates);
}

#[test]
fn authn_request_is_deflated_and_carries_relay_state() {
    use std::io::Read;
    let url = authn_request_url(
        &settings(),
        &Sp {
            entity_id: ENTITY,
            acs_url: ACS,
        },
        "_abc",
        "relay-1",
        None,
    )
    .unwrap();
    assert!(url.starts_with("https://idp.acme.test/sso/saml?SAMLRequest="));
    assert!(url.ends_with("&RelayState=relay-1"));
    let encoded = url
        .split("SAMLRequest=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let deflated = STANDARD
        .decode(urlencoding::decode(encoded).unwrap().as_bytes())
        .unwrap();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&deflated[..])
        .read_to_string(&mut xml)
        .unwrap();
    assert!(xml.contains(r#"ID="_abc""#));
    assert!(xml.contains(&format!(r#"AssertionConsumerServiceURL="{ACS}""#)));
    assert!(xml.contains(&format!("<saml:Issuer>{ENTITY}</saml:Issuer>")));
}

#[test]
fn sp_metadata_names_entity_and_acs() {
    let xml = sp_metadata(&Sp {
        entity_id: ENTITY,
        acs_url: ACS,
    });
    assert!(xml.contains(&format!(r#"entityID="{ENTITY}""#)));
    assert!(xml.contains(&format!(r#"Location="{ACS}""#)));
    assert!(xml.contains(r#"WantAssertionsSigned="true""#));
    // Our own metadata parses with our own parser.
    crate::c14n::parse(&xml).unwrap();
}


/// [labac] every attribute value is read, and the groups among them - none in this fixture
#[test]
fn every_attribute_value_is_read_for_labac() {
    let a = verify("signed_assertion").unwrap();
    assert!(a.attributes.contains(&("mail".to_string(), "bob@acme.com".to_string())), "{:?}", a.attributes);
    assert!(a.attributes.contains(&("displayName".to_string(), "Bob Builder".to_string())), "{:?}", a.attributes);
    assert!(a.groups.is_empty());
    assert!(GROUPS_ATTRIBUTES.contains(&"memberof"));
}
