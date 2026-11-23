//! SAML 2.0 service provider (feature `saml`): SP metadata, the AuthnRequest
//! (HTTP-Redirect binding) and verification of the IdP's Response
//! (HTTP-POST binding).
//!
//! **Status: needs an external security review before a customer connection
//! is switched to SAML** (`SSO.md` §7). The verifier is deliberately narrow,
//! and every narrowing is a refusal rather than a fallback:
//!
//! * accepted: a signed `Assertion`, or a signed `Response` containing exactly
//!   one `Assertion`; RSA-SHA256/512 over exclusive C14N; SHA-256/512
//!   digests; exactly one `Reference`, pointing at the signed element's own
//!   `ID`, with the enveloped-signature and exclusive-C14N transforms;
//! * refused: `DOCTYPE`, `EncryptedAssertion`, more than one `Assertion`
//!   anywhere in the document, duplicate `ID`s, SHA-1, any other transform,
//!   an IdP-initiated response (no `InResponseTo`);
//! * the signing key is one of the certificates the customer configured —
//!   `KeyInfo` in the document is ignored, never trusted;
//! * every value the caller gets is read from inside the element the
//!   signature covers, located structurally (the one `Assertion`, child of the
//!   root), never by following an `ID` the document chooses. That plus the
//!   single-assertion and unique-ID rules is the signature-wrapping defence.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};

use crate::c14n::{self, Doc};

/// One customer IdP, as the service provider needs it.
#[derive(Clone, Debug)]
pub struct SamlSettings {
    pub idp_entity_id: String,
    /// HTTP-Redirect binding endpoint.
    pub sso_url: String,
    /// DER certificates the IdP signs with. More than one only during the
    /// IdP's own certificate rollover.
    pub certificates: Vec<Vec<u8>>,
}

pub const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const NAMEID_EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// Clock skew allowed on every SAML time check.
const SKEW_SECS: i64 = 120;
/// A Response larger than this is refused before it is parsed.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Attribute names IdPs commonly put the email address under.
const EMAIL_ATTRIBUTES: &[&str] = &[
    "email",
    "mail",
    "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
];
const NAME_ATTRIBUTES: &[&str] = &[
    "name",
    "displayname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "http://schemas.microsoft.com/identity/claims/displayname",
    "urn:oid:2.16.840.1.113730.3.1.241",
];

/// This SP, as one connection presents it.
pub struct Sp<'a> {
    pub entity_id: &'a str,
    pub acs_url: &'a str,
}

/// What a verified assertion says about the person.
#[derive(Debug, Clone)]
pub struct Assertion {
    /// The `NameID` — the IdP's identifier for the person.
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    /// [labac] the groups attribute's values (`groups`, `memberOf`, the Microsoft groups claim)
    pub groups: Vec<String>,
    /// [labac] every attribute value, as (name, value): what labac's rules map
    pub attributes: Vec<(String, String)>,
}

/// [labac] the attribute names a groups list comes under
pub const GROUPS_ATTRIBUTES: &[&str] = &["groups", "memberof", "group",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", "http://schemas.xmlsoap.org/claims/group"];

/// `_` plus 40 hex characters. An xs:ID must not start with a digit.
pub fn new_request_id() -> String {
    let secret = crate::token::secret();
    format!("_{}", &crate::token::hash(&secret)[..40])
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The IdP redirect carrying a deflated, base64'd AuthnRequest and our
/// `RelayState` (the single-use state value).
pub fn authn_request_url(
    settings: &SamlSettings,
    sp: &Sp<'_>,
    request_id: &str,
    relay_state: &str,
    _login_hint: Option<&str>,
) -> anyhow::Result<String> {
    use std::io::Write;
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ");
    let xml = format!(
        "<samlp:AuthnRequest xmlns:samlp=\"{PROTOCOL_NS}\" xmlns:saml=\"{ASSERTION_NS}\" \
         ID=\"{id}\" Version=\"2.0\" IssueInstant=\"{issue_instant}\" Destination=\"{dest}\" \
         AssertionConsumerServiceURL=\"{acs}\" \
         ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">\
         <saml:Issuer>{issuer}</saml:Issuer>\
         <samlp:NameIDPolicy Format=\"{NAMEID_EMAIL}\" AllowCreate=\"true\"/>\
         </samlp:AuthnRequest>",
        id = xml_escape(request_id),
        dest = xml_escape(&settings.sso_url),
        acs = xml_escape(sp.acs_url),
        issuer = xml_escape(sp.entity_id),
    );
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(xml.as_bytes())?;
    let deflated = encoder.finish()?;
    let sep = if settings.sso_url.contains('?') { '&' } else { '?' };
    Ok(format!(
        "{}{sep}SAMLRequest={}&RelayState={}",
        settings.sso_url,
        urlencoding::encode(&STANDARD.encode(deflated)),
        urlencoding::encode(relay_state)
    ))
}

/// SP metadata listing several ACS URLs (one per site the connection signs
/// in to), all HTTP-POST, the first the default.
pub fn sp_metadata_for(entity_id: &str, acs_urls: &[&str]) -> String {
    let acs: String = acs_urls
        .iter()
        .enumerate()
        .map(|(i, url)| {
            format!(
                "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
                 Location=\"{}\" index=\"{i}\" isDefault=\"{}\"/>",
                xml_escape(url),
                i == 0
            )
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{entity}\">\
         <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" \
         protocolSupportEnumeration=\"{PROTOCOL_NS}\">\
         <md:NameIDFormat>{NAMEID_EMAIL}</md:NameIDFormat>{acs}\
         </md:SPSSODescriptor></md:EntityDescriptor>\n",
        entity = xml_escape(entity_id),
    )
}

/// SP metadata for the customer to import into their IdP.
pub fn sp_metadata(sp: &Sp<'_>) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"{entity}\">\
         <md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"true\" \
         protocolSupportEnumeration=\"{PROTOCOL_NS}\">\
         <md:NameIDFormat>{NAMEID_EMAIL}</md:NameIDFormat>\
         <md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
         Location=\"{acs}\" index=\"0\" isDefault=\"true\"/>\
         </md:SPSSODescriptor></md:EntityDescriptor>\n",
        entity = xml_escape(sp.entity_id),
        acs = xml_escape(sp.acs_url),
    )
}

/// Verifies a base64 `SAMLResponse` and returns what it asserts.
pub fn verify_response(
    saml_response_b64: &str,
    settings: &SamlSettings,
    sp: &Sp<'_>,
    expected_request_id: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<Assertion> {
    let compact: String = saml_response_b64.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() > MAX_RESPONSE_BYTES * 4 / 3 + 4 {
        anyhow::bail!("response too large");
    }
    let raw = STANDARD.decode(compact)?;
    if raw.len() > MAX_RESPONSE_BYTES {
        anyhow::bail!("response too large");
    }
    let xml = std::str::from_utf8(&raw)?;
    let doc = c14n::parse(xml)?;
    let root = Doc::ROOT;

    let root_el = doc.element(root).ok_or_else(|| anyhow::anyhow!("no root"))?;
    if root_el.ns.as_deref() != Some(PROTOCOL_NS) || root_el.local != "Response" {
        anyhow::bail!("not a samlp:Response");
    }

    // Structure first: exactly one Assertion in the whole document, as a
    // direct child of the Response; no encrypted ones; no duplicate IDs.
    let all = doc.descendants(root);
    let mut assertions = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for &n in &all {
        let e = doc.element(n).expect("descendants are elements");
        if e.ns.as_deref() == Some(ASSERTION_NS) && e.local == "EncryptedAssertion" {
            anyhow::bail!("encrypted assertions are not supported");
        }
        if e.ns.as_deref() == Some(ASSERTION_NS) && e.local == "Assertion" {
            assertions.push(n);
        }
        if let Some(id) = doc.attr(n, "ID") {
            if !ids.insert(id.to_string()) {
                anyhow::bail!("duplicate ID {id}");
            }
        }
    }
    let [assertion] = assertions[..] else {
        anyhow::bail!("expected exactly one Assertion, found {}", assertions.len());
    };
    if doc.nodes[assertion].parent != Some(root) {
        anyhow::bail!("the Assertion is not a direct child of the Response");
    }

    // Status.
    let status = doc
        .child_named(root, PROTOCOL_NS, "Status")
        .and_then(|s| doc.child_named(s, PROTOCOL_NS, "StatusCode"))
        .and_then(|c| doc.attr(c, "Value"))
        .ok_or_else(|| anyhow::anyhow!("no status"))?;
    if status != STATUS_SUCCESS {
        anyhow::bail!("IdP status {status}");
    }

    // Which element is signed: the Assertion if it carries its own
    // signature, else the Response. Either way the Assertion is inside it.
    let signed = if single_signature(&doc, assertion)?.is_some() {
        assertion
    } else if single_signature(&doc, root)?.is_some() {
        root
    } else {
        anyhow::bail!("neither the Assertion nor the Response is signed");
    };
    let signature = single_signature(&doc, signed)?.expect("checked above");
    verify_signature(&doc, signed, signature, &settings.certificates)?;
    debug_assert!(doc.is_within(assertion, signed));

    // Response-level checks.
    if let Some(dest) = doc.attr(root, "Destination") {
        if dest != sp.acs_url {
            anyhow::bail!("Destination is not our ACS");
        }
    }
    if let Some(irt) = doc.attr(root, "InResponseTo") {
        if irt != expected_request_id {
            anyhow::bail!("Response InResponseTo does not match");
        }
    }
    if let Some(issuer) = doc.child_named(root, ASSERTION_NS, "Issuer") {
        if doc.text(issuer).trim() != settings.idp_entity_id {
            anyhow::bail!("Response Issuer is not the configured IdP");
        }
    }

    // Assertion-level checks, all read from inside the signed element.
    let issuer = doc
        .child_named(assertion, ASSERTION_NS, "Issuer")
        .ok_or_else(|| anyhow::anyhow!("Assertion has no Issuer"))?;
    if doc.text(issuer).trim() != settings.idp_entity_id {
        anyhow::bail!("Assertion Issuer is not the configured IdP");
    }

    let subject = doc
        .child_named(assertion, ASSERTION_NS, "Subject")
        .ok_or_else(|| anyhow::anyhow!("Assertion has no Subject"))?;
    let bearer_ok = doc
        .children_named(subject, ASSERTION_NS, "SubjectConfirmation")
        .filter(|&sc| doc.attr(sc, "Method") == Some(BEARER))
        .filter_map(|sc| doc.child_named(sc, ASSERTION_NS, "SubjectConfirmationData"))
        .any(|scd| {
            doc.attr(scd, "Recipient") == Some(sp.acs_url)
                && doc.attr(scd, "InResponseTo") == Some(expected_request_id)
                && doc
                    .attr(scd, "NotOnOrAfter")
                    .and_then(parse_time)
                    .is_some_and(|t| now < t + chrono::Duration::seconds(SKEW_SECS))
                && doc
                    .attr(scd, "NotBefore")
                    .map(|nb| parse_time(nb).is_some_and(|t| now + chrono::Duration::seconds(SKEW_SECS) >= t))
                    .unwrap_or(true)
        });
    if !bearer_ok {
        anyhow::bail!("no bearer SubjectConfirmation for this request, recipient and time");
    }

    let conditions = doc
        .child_named(assertion, ASSERTION_NS, "Conditions")
        .ok_or_else(|| anyhow::anyhow!("Assertion has no Conditions"))?;
    if let Some(nb) = doc.attr(conditions, "NotBefore") {
        let t = parse_time(nb).ok_or_else(|| anyhow::anyhow!("bad NotBefore"))?;
        if now + chrono::Duration::seconds(SKEW_SECS) < t {
            anyhow::bail!("assertion not yet valid");
        }
    }
    let not_after = doc
        .attr(conditions, "NotOnOrAfter")
        .and_then(parse_time)
        .ok_or_else(|| anyhow::anyhow!("Conditions without NotOnOrAfter"))?;
    if now >= not_after + chrono::Duration::seconds(SKEW_SECS) {
        anyhow::bail!("assertion expired");
    }
    let audience_ok = doc
        .children_named(conditions, ASSERTION_NS, "AudienceRestriction")
        .flat_map(|ar| doc.children_named(ar, ASSERTION_NS, "Audience").collect::<Vec<_>>())
        .any(|a| doc.text(a).trim() == sp.entity_id);
    if !audience_ok {
        anyhow::bail!("assertion is not for this SP");
    }

    let name_id = doc
        .child_named(subject, ASSERTION_NS, "NameID")
        .ok_or_else(|| anyhow::anyhow!("Subject has no NameID"))?;
    let subject_value = doc.text(name_id).trim().to_string();
    if subject_value.is_empty() {
        anyhow::bail!("empty NameID");
    }

    let attribute = |names: &[&str]| -> Option<String> {
        let statement = doc.child_named(assertion, ASSERTION_NS, "AttributeStatement")?;
        doc.children_named(statement, ASSERTION_NS, "Attribute")
            .find(|&a| {
                doc.attr(a, "Name")
                    .is_some_and(|n| names.iter().any(|want| n.eq_ignore_ascii_case(want)))
            })
            .and_then(|a| doc.child_named(a, ASSERTION_NS, "AttributeValue"))
            .map(|v| doc.text(v).trim().to_string())
            .filter(|v| !v.is_empty())
    };

    let email = if doc.attr(name_id, "Format") == Some(NAMEID_EMAIL) {
        Some(subject_value.clone())
    } else {
        attribute(EMAIL_ATTRIBUTES)
    };
    let name = attribute(NAME_ATTRIBUTES).or_else(|| {
        let given = attribute(&["givenname", "firstname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"]);
        let sur = attribute(&["surname", "sn", "lastname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"]);
        let full = [given, sur].into_iter().flatten().collect::<Vec<_>>().join(" ");
        (!full.is_empty()).then_some(full)
    });

    // [labac] every value of every attribute, and the groups among them
    let mut attributes = Vec::new();
    if let Some(statement) = doc.child_named(assertion, ASSERTION_NS, "AttributeStatement") {
        for a in doc.children_named(statement, ASSERTION_NS, "Attribute") {
            let Some(n) = doc.attr(a, "Name") else { continue };
            for v in doc.children_named(a, ASSERTION_NS, "AttributeValue") {
                let v = doc.text(v).trim().to_string();
                if !v.is_empty() {
                    attributes.push((n.to_string(), v));
                }
            }
        }
    }
    let groups = attributes.iter()
        .filter(|(n, _)| GROUPS_ATTRIBUTES.iter().any(|g| n.eq_ignore_ascii_case(g)))
        .map(|(_, v)| v.clone()).collect();

    Ok(Assertion {
        subject: subject_value,
        email,
        name,
        groups,
        attributes,
    })
}

/// The `ds:Signature` that is a direct child of `id`, if exactly one is.
fn single_signature(doc: &Doc, id: usize) -> anyhow::Result<Option<usize>> {
    let sigs: Vec<usize> = doc.children_named(id, DSIG_NS, "Signature").collect();
    match sigs[..] {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => anyhow::bail!("more than one Signature on one element"),
    }
}

fn prefix_list(doc: &Doc, method: usize) -> Vec<String> {
    doc.children_named(method, EXC_C14N, "InclusiveNamespaces")
        .next()
        .and_then(|n| doc.attr(n, "PrefixList"))
        .map(|list| list.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

fn verify_signature(doc: &Doc, signed: usize, signature: usize, certificates: &[Vec<u8>]) -> anyhow::Result<()> {
    let one = |parent: usize, local: &str| -> anyhow::Result<usize> {
        let found: Vec<usize> = doc.children_named(parent, DSIG_NS, local).collect();
        match found[..] {
            [only] => Ok(only),
            _ => anyhow::bail!("expected exactly one ds:{local}"),
        }
    };

    let signed_info = one(signature, "SignedInfo")?;
    let c14n_method = one(signed_info, "CanonicalizationMethod")?;
    if doc.attr(c14n_method, "Algorithm") != Some(EXC_C14N) {
        anyhow::bail!("SignedInfo must use exclusive C14N");
    }
    let sig_method = one(signed_info, "SignatureMethod")?;
    let algorithm: &'static ring::signature::RsaParameters = match doc.attr(sig_method, "Algorithm") {
        Some(RSA_SHA256) => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        Some(RSA_SHA512) => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        other => anyhow::bail!("signature algorithm {other:?} is not accepted"),
    };

    let reference = one(signed_info, "Reference")?;
    let signed_id = doc
        .attr(signed, "ID")
        .ok_or_else(|| anyhow::anyhow!("signed element has no ID"))?;
    if doc.attr(reference, "URI") != Some(&format!("#{signed_id}")) {
        anyhow::bail!("Reference does not point at the signed element");
    }

    let transforms = one(reference, "Transforms")?;
    let mut saw_enveloped = false;
    let mut saw_c14n = false;
    let mut digest_prefixes = Vec::new();
    for t in doc.children_named(transforms, DSIG_NS, "Transform") {
        match doc.attr(t, "Algorithm") {
            Some(ENVELOPED) if !saw_enveloped => saw_enveloped = true,
            Some(EXC_C14N) if !saw_c14n => {
                saw_c14n = true;
                digest_prefixes = prefix_list(doc, t);
            }
            other => anyhow::bail!("transform {other:?} is not accepted"),
        }
    }
    if !saw_enveloped || !saw_c14n {
        anyhow::bail!("Reference needs exactly the enveloped-signature and exclusive C14N transforms");
    }

    let digest_method = one(reference, "DigestMethod")?;
    let canonical = c14n::exclusive(doc, signed, Some(signature), &digest_prefixes);
    let computed = match doc.attr(digest_method, "Algorithm") {
        Some(SHA256) => ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes()),
        Some(SHA512) => ring::digest::digest(&ring::digest::SHA512, canonical.as_bytes()),
        other => anyhow::bail!("digest algorithm {other:?} is not accepted"),
    };
    let claimed = decode_b64_text(&doc.text(one(reference, "DigestValue")?))?;
    if claimed.as_slice() != computed.as_ref() {
        anyhow::bail!("digest does not match the signed element");
    }

    let signature_value = decode_b64_text(&doc.text(one(signature, "SignatureValue")?))?;
    let signed_info_c14n = c14n::exclusive(doc, signed_info, None, &prefix_list(doc, c14n_method));

    for der in certificates {
        let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
            continue;
        };
        let spki = cert.public_key();
        let key = ring::signature::UnparsedPublicKey::new(algorithm, spki.subject_public_key.data.as_ref());
        if key
            .verify(signed_info_c14n.as_bytes(), &signature_value)
            .is_ok()
        {
            return Ok(());
        }
    }
    anyhow::bail!("signature does not verify against any configured IdP certificate")
}

fn decode_b64_text(text: &str) -> anyhow::Result<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    Ok(STANDARD.decode(compact)?)
}

fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

/// Reads the IdP's signing certificates out of its metadata XML — what the
/// customer usually pastes. Returns `(entity_id, sso_url, certificates)`.
/// The metadata itself is *not* trusted for anything else: it is a
/// convenience for filling in three fields the customer could type.
pub fn parse_idp_metadata(xml: &str) -> anyhow::Result<(String, String, Vec<Vec<u8>>)> {
    const MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
    let doc = c14n::parse(xml)?;
    let root = Doc::ROOT;
    let root_el = doc.element(root).ok_or_else(|| anyhow::anyhow!("no root"))?;
    if root_el.ns.as_deref() != Some(MD) || root_el.local != "EntityDescriptor" {
        anyhow::bail!("not an md:EntityDescriptor");
    }
    let entity_id = doc
        .attr(root, "entityID")
        .ok_or_else(|| anyhow::anyhow!("no entityID"))?
        .to_string();
    let idp = doc
        .child_named(root, MD, "IDPSSODescriptor")
        .ok_or_else(|| anyhow::anyhow!("no IDPSSODescriptor"))?;
    let sso_url = doc
        .children_named(idp, MD, "SingleSignOnService")
        .find(|&s| doc.attr(s, "Binding") == Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"))
        .and_then(|s| doc.attr(s, "Location"))
        .ok_or_else(|| anyhow::anyhow!("no HTTP-Redirect SingleSignOnService"))?
        .to_string();
    let mut certs = Vec::new();
    for kd in doc.children_named(idp, MD, "KeyDescriptor") {
        if doc.attr(kd, "use").is_some_and(|u| u != "signing") {
            continue;
        }
        for n in doc.descendants(kd) {
            let e = doc.element(n).expect("element");
            if e.ns.as_deref() == Some(DSIG_NS) && e.local == "X509Certificate" {
                certs.push(decode_b64_text(&doc.text(n))?);
            }
        }
    }
    if certs.is_empty() {
        anyhow::bail!("no signing certificate in the metadata");
    }
    Ok((entity_id, sso_url, certs))
}

/// One PEM or bare-base64 certificate to DER, checking it parses.
pub fn certificate_der(pem_or_b64: &str) -> anyhow::Result<Vec<u8>> {
    let body: String = pem_or_b64
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = STANDARD.decode(body)?;
    x509_parser::parse_x509_certificate(&der).map_err(|e| anyhow::anyhow!("not an X.509 certificate: {e}"))?;
    Ok(der)
}

// test documents: the signer other crates' tests use too, and the maker of this crate's own set
#[cfg(any(test, feature = "test-support"))]
pub(crate) mod sign;
#[cfg(test)]
mod fixture_gen;
#[cfg(test)]
mod tests;
