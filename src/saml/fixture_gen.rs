//! The SAML test documents, made where they are not on the machine (nothing
//! with a name or a key in it has to be pushed). `tests/fixtures/saml/` as it was first made holds
//! documents signed by `signxml`, an independent XML-DSig implementation: where that set is
//! there, the tests read it, and it is the one that checks this crate's verifier against another
//! implementation. Where the directory is not there - a fresh clone, CI - this makes the same
//! set: two throwaway keys and their self-signed certificates by `openssl`, the documents signed
//! by this crate's own signer (`sign.rs`), the attack variants derived from them the way the
//! first set's were. That set checks every rule of the verifier but one: its C14N is checked
//! only against itself there (`c14n.rs` has its own cases, against libxml2).
//!
//! No private key outlives the making: the two keys sign, and are removed.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::sign::{self, SLOT};
use crate::fixture_keys::{self, PrivateTemp};

/// The directory the SAML test documents are read from: the set that is there, else one made now
pub(super) fn dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| fixture_keys::there_or_made(there, make))
}

/// A whole set: its certificate is written last
fn there(fixtures: &Path) -> Option<PathBuf> {
    let saml = fixtures.join("saml");
    (saml.join("idp_cert.pem").is_file() && saml.join("signed_assertion.xml").is_file()).then_some(saml)
}

/// A key that signs while the set is made, and its self-signed certificate
struct Signer {
    key: PrivateTemp,
    key_pem: String,
    cert_pem: String,
}

impl Signer {
    fn new(saml: &Path, what: &str, subject: &str) -> io::Result<Signer> {
        let key = PrivateTemp::new(saml, what)?;
        fixture_keys::openssl(&["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out"], key.path())?;
        let cert = fixture_keys::openssl(&["req", "-x509", "-new", "-sha256", "-days", "36500", "-subj", subject, "-key"], key.path())?;
        Ok(Signer { key_pem: std::fs::read_to_string(key.path())?, cert_pem: String::from_utf8_lossy(&cert).into_owned(), key })
    }

    fn sign(&self, unsigned: &str, element: &str) -> String {
        sign::sign_enveloped(unsigned, element, &self.key_pem, Some(&self.cert_pem))
    }
}

/// The response every document starts from: one assertion about bob@acme.com, for the request
/// `_req1`, valid 09:59 to 10:05 on 2026-10-04
const BASE: &str = r###"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="_resp1" Version="2.0" IssueInstant="2026-10-04T10:00:00Z" Destination="https://register.test/api/account/sso/acme/acs" InResponseTo="_req1">
  <saml:Issuer>https://idp.acme.test</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_assert1" Version="2.0" IssueInstant="2026-10-04T10:00:00Z">
    <saml:Issuer>https://idp.acme.test</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@acme.com</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_req1" NotOnOrAfter="2026-10-04T10:05:00Z" Recipient="https://register.test/api/account/sso/acme/acs"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-10-04T09:59:00Z" NotOnOrAfter="2026-10-04T10:05:00Z">
      <saml:AudienceRestriction><saml:Audience>https://register.test/api/account/sso/acme/metadata</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2026-10-04T10:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="mail"><saml:AttributeValue xsi:type="xs:string">bob@acme.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="displayName"><saml:AttributeValue xsi:type="xs:string">Bob Builder</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"###;

const ISSUER: &str = "<saml:Issuer>https://idp.acme.test</saml:Issuer>";
const NAME_ID: &str = r#"<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@acme.com</saml:NameID>"#;
const MAIL: &str = r#"<saml:AttributeValue xsi:type="xs:string">bob@acme.com</saml:AttributeValue>"#;

/// `doc` with each `from` put as `to` - every one of its `count` places, and no other number
fn put(doc: &str, changes: &[(&str, &str, usize)]) -> String {
    let mut out = doc.to_string();
    for (from, to, count) in changes {
        assert_eq!(out.matches(from).count(), *count, "{from} in the document");
        out = out.replace(from, to);
    }
    out
}

/// `doc` with the signature's slot after the `Issuer` of its Response (the first) or of its
/// Assertion (the second)
fn slot(doc: &str, element: &str) -> String {
    let nth = if element == "Response" { 0 } else { 1 };
    let (at, issuer) = doc.match_indices("</saml:Issuer>").nth(nth).expect("an Issuer");
    let end = at + issuer.len();
    format!("{}{SLOT}{}", &doc[..end], &doc[end..])
}

/// The first Assertion element of `doc`, whole
fn assertion(doc: &str) -> &str {
    let from = doc.find("<saml:Assertion ").expect("an Assertion");
    let to = doc.find("</saml:Assertion>").expect("its end") + "</saml:Assertion>".len();
    &doc[from..to]
}

/// Every document of the set, by its file's name
fn documents(idp: &Signer, attacker: &Signer, saml: &Path) -> io::Result<Vec<(&'static str, String)>> {
    let signed = |doc: &str| idp.sign(&slot(doc, "Assertion"), "Assertion");
    let good = signed(BASE);
    let ceo = |doc: &str| put(doc, &[(">bob@acme.com</saml:NameID>", ">ceo@acme.com</saml:NameID>", 1)]);
    // signature wrapping: the signed assertion moved where nobody looks for one, another in its place
    let wrapped = |forged: &str| good.replace(assertion(&good), &format!("<samlp:Extensions>{}</samlp:Extensions>{forged}", assertion(&good)));
    Ok(vec![
        ("unsigned.xml", BASE.to_string()),
        ("signed_assertion.xml", good.clone()),
        ("signed_response.xml", idp.sign(&slot(BASE, "Response"), "Response")),
        // signed as they are: what is refused, or read, is what they say
        ("persistent_nameid.xml", signed(&put(BASE, &[(NAME_ID, r#"<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">a1b2c3</saml:NameID>"#, 1)]))),
        ("comment_in_nameid.xml", signed(&put(BASE, &[
            (NAME_ID, r#"<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">bob@acme.com<!---->.evil.test</saml:NameID>"#, 1),
            (MAIL, r#"<saml:AttributeValue xsi:type="xs:string">bob@acme.com.evil.test</saml:AttributeValue>"#, 1),
        ]))),
        ("expired.xml", signed(&put(BASE, &[(r#"NotOnOrAfter="2026-10-04T10:05:00Z""#, r#"NotOnOrAfter="2026-10-04T09:30:00Z""#, 2)]))),
        ("other_issuer.xml", signed(&put(BASE, &[(ISSUER, "<saml:Issuer>https://idp.other.test</saml:Issuer>", 2)]))),
        ("wrong_audience.xml", signed(&put(BASE, &[
            ("<saml:Audience>https://register.test/api/account/sso/acme/metadata</saml:Audience>",
             "<saml:Audience>https://dash.test/api/account/sso/acme/metadata</saml:Audience>", 1),
        ]))),
        ("wrong_recipient.xml", signed(&put(BASE, &[
            (r#"Destination="https://register.test/api/account/sso/acme/acs""#, r#"Destination="https://evil.test/acs""#, 1),
            (r#"Recipient="https://register.test/api/account/sso/acme/acs""#, r#"Recipient="https://evil.test/acs""#, 1),
        ]))),
        ("wrong_request.xml", signed(&put(BASE, &[(r#"InResponseTo="_req1""#, r#"InResponseTo="_someone_else""#, 2)]))),
        ("attacker_signed.xml", attacker.sign(&slot(BASE, "Assertion"), "Assertion")),
        ("sha1_method.xml", sha1_signed(idp, saml)?),
        // changed after signing
        ("tampered_nameid.xml", ceo(&good)),
        ("doctype.xml", format!(r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e "x">]>{good}"#)),
        ("encrypted.xml", good.replacen(ISSUER, &format!("{ISSUER}<saml:EncryptedAssertion/>"), 1)),
        ("xsw_hidden_original.xml", wrapped(&put(&ceo(assertion(BASE)), &[(r#"ID="_assert1""#, r#"ID="_evil""#, 1)]))),
        ("xsw_duplicate_id.xml", wrapped(&ceo(assertion(&good)))),
    ])
}

const RSA_SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

/// The good assertion under an RSA-SHA1 signature - a real one, by `openssl`, which the verifier
/// refuses for its method. Where `openssl` will not sign with SHA-1 it says so, and the document
/// carries the SHA-256 signature under SHA-1's name: refused for the same method, before any
/// signature is checked.
fn sha1_signed(idp: &Signer, saml: &Path) -> io::Result<String> {
    let unsigned = slot(BASE, "Assertion");
    let by_openssl = |bytes: &[u8]| -> Vec<u8> {
        sha1_signature(idp, saml, bytes).unwrap_or_else(|e| {
            // [review 2026-11-15, the second] not in silence: which signature the document carries is said
            eprintln!("sha1_method.xml: openssl would not sign with SHA-1 ({e}); it carries a SHA-256 signature under SHA-1's name");
            sign::rsa_sha256(&idp.key_pem, bytes)
        })
    };
    let signature = sign::signature(&unsigned, "Assertion", RSA_SHA1, &by_openssl, Some(&idp.cert_pem));
    Ok(unsigned.replacen(SLOT, &signature, 1))
}

/// RSA PKCS#1 v1.5 over SHA-1, by `openssl`: this crate's own libraries do not sign with it
fn sha1_signature(idp: &Signer, saml: &Path, bytes: &[u8]) -> io::Result<Vec<u8>> {
    let data = saml.join(format!(".making-signed-info-{}.tmp", std::process::id()));
    let key = idp.key.path().to_string_lossy().into_owned();
    let made = std::fs::write(&data, bytes).and_then(|()| fixture_keys::openssl(&["dgst", "-sha1", "-sign", &key], &data));
    let _ = std::fs::remove_file(&data);
    made
}

fn metadata(cert_pem: &str) -> String {
    format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://idp.acme.test">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.acme.test/sso/saml"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"#,
        sign::pem_body(cert_pem)
    )
}

/// The whole set under `fixtures/saml`, the IdP's certificate last: a set that is found is whole
fn make(fixtures: &Path) -> io::Result<()> {
    let saml = fixtures.join("saml");
    std::fs::create_dir_all(&saml)?;
    let idp = Signer::new(&saml, "idp", "/CN=idp.acme.test (signon test fixture)")?;
    let attacker = Signer::new(&saml, "attacker", "/CN=attacker (signon test fixture)")?;
    for (name, document) in documents(&idp, &attacker, &saml)? {
        std::fs::write(saml.join(name), document)?;
    }
    std::fs::write(saml.join("attacker_cert.pem"), &attacker.cert_pem)?;
    std::fs::write(saml.join("idp_metadata.xml"), metadata(&idp.cert_pem))?;
    fixture_keys::write_whole(&saml.join("idp_cert.pem"), idp.cert_pem.as_bytes())
    // the two keys are removed here, with their temp files
}

#[cfg(test)]
mod tests {
    use super::super::*;
    use super::*;

    /// A set made from nothing passes what the checked-in kind of set passes: the good documents
    /// verify and say who they are about, every attack and mismatch is refused, the validity
    /// window holds with its skew, the metadata gives the same certificate - and no private key
    /// is left in the directory.
    #[test]
    fn a_set_made_here_passes_the_same_checks() {
        let fixtures = std::env::temp_dir().join(format!("signon-saml-gen-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&fixtures);
        assert!(there(&fixtures).is_none());
        make(&fixtures).expect("openssl makes the keys");
        let saml = there(&fixtures).expect("a whole set");
        let read = |name: &str| std::fs::read_to_string(saml.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let settings = SamlSettings {
            idp_entity_id: "https://idp.acme.test".into(),
            sso_url: "https://idp.acme.test/sso/saml".into(),
            certificates: vec![certificate_der(&read("idp_cert.pem")).unwrap()],
        };
        let sp = Sp { entity_id: "https://register.test/api/account/sso/acme/metadata", acs_url: "https://register.test/api/account/sso/acme/acs" };
        let verify_at = |name: &str, at: &str| verify_response(&STANDARD.encode(read(&format!("{name}.xml"))), &settings, &sp, "_req1", at.parse().unwrap());
        let verify = |name: &str| verify_at(name, "2026-10-04T10:01:00Z");

        let a = verify("signed_assertion").unwrap();
        assert_eq!((a.subject.as_str(), a.email.as_deref(), a.name.as_deref()), ("bob@acme.com", Some("bob@acme.com"), Some("Bob Builder")));
        assert_eq!(verify("signed_response").unwrap().email.as_deref(), Some("bob@acme.com"));
        let a = verify("persistent_nameid").unwrap();
        assert_eq!((a.subject.as_str(), a.email.as_deref()), ("a1b2c3", Some("bob@acme.com")));
        let a = verify("comment_in_nameid").unwrap();
        assert_eq!((a.subject.as_str(), a.email.as_deref()), ("bob@acme.com.evil.test", Some("bob@acme.com.evil.test")));

        for name in ["unsigned", "attacker_signed", "tampered_nameid", "sha1_method", "wrong_audience", "wrong_recipient", "wrong_request",
                     "other_issuer", "xsw_hidden_original", "xsw_duplicate_id", "doctype", "encrypted", "expired"] {
            assert!(verify(name).is_err(), "{name} was accepted");
        }
        // each of these is validly signed, so what refuses it is what it says, not its signature:
        // the same documents pass once the one thing they get wrong is what is asked for
        let other_sp = Sp { entity_id: "https://dash.test/api/account/sso/acme/metadata", acs_url: sp.acs_url };
        let at = "2026-10-04T10:01:00Z".parse().unwrap();
        assert!(verify_response(&STANDARD.encode(read("wrong_audience.xml")), &settings, &other_sp, "_req1", at).is_ok(), "wrong_audience is signed");
        assert!(verify_response(&STANDARD.encode(read("wrong_request.xml")), &settings, &sp, "_someone_else", at).is_ok(), "wrong_request is signed");
        assert!(verify_at("expired", "2026-10-04T09:20:00Z").is_err(), "before its NotBefore");
        let attacker = SamlSettings { certificates: vec![certificate_der(&read("attacker_cert.pem")).unwrap()], ..settings.clone() };
        assert!(verify_response(&STANDARD.encode(read("attacker_signed.xml")), &attacker, &sp, "_req1", at).is_ok(), "the attacker's signature is a real one");

        // [review 2026-11-15, the second] the SHA-1 document is refused for its method, whichever
        // signature it carries; and where this machine's openssl signs with SHA-1, the signature
        // is a real SHA-1 one - the cert's key verifies it as that
        let why = verify("sha1_method").unwrap_err().to_string();
        assert!(why.contains("signature algorithm") && why.contains("rsa-sha1"), "{why}");
        let probe = Signer::new(&saml, "probe", "/CN=probe").unwrap();
        match sha1_signature(&probe, &saml, b"what is signed") {
            Ok(signature) => {
                let der = certificate_der(&probe.cert_pem).unwrap();
                let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
                let key = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
                    cert.public_key().subject_public_key.data.as_ref(),
                );
                key.verify(b"what is signed", &signature).expect("a real RSA-SHA1 signature");
            }
            Err(e) => eprintln!("openssl does not sign with SHA-1 here ({e}): the fallback made sha1_method.xml"),
        }
        drop(probe);

        assert!(verify_at("signed_assertion", "2026-10-04T11:00:00Z").is_err(), "an hour after it lapsed");
        assert!(verify_at("signed_assertion", "2026-10-04T09:00:00Z").is_err(), "well before NotBefore");
        assert!(verify_at("signed_assertion", "2026-10-04T09:58:00Z").is_ok(), "within the skew");

        let (entity, sso, certs) = parse_idp_metadata(&read("idp_metadata.xml")).unwrap();
        assert_eq!((entity.as_str(), sso.as_str()), ("https://idp.acme.test", "https://idp.acme.test/sso/saml"));
        assert_eq!(certs, settings.certificates);

        // 17 documents, the metadata and two certificates - and nothing else: no key, no temp file
        let mut names: Vec<String> = std::fs::read_dir(&saml).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names.len(), 20, "{names:?}");
        assert!(names.iter().all(|n| n.ends_with(".xml") || n.ends_with("_cert.pem")), "{names:?}");
        for name in &names {
            assert!(!read(name).contains("PRIVATE KEY"), "{name} holds a private key");
        }
        std::fs::remove_dir_all(&fixtures).unwrap();
    }
}
