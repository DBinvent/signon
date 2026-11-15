//! An enveloped XML signature over one element of a test document: what `testing::saml` hands
//! other crates' tests, and what makes the SAML test documents on a machine that does not have
//! them (`fixture_gen`). It uses this crate's own C14N, so a document it signs says nothing
//! about the verifier's C14N - only the documents an independent implementation signed do.

use base64::Engine;

use crate::c14n;

const DS: &str = "http://www.w3.org/2000/09/xmldsig#";
const EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub(crate) const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

/// Where the signature goes in a document that is to be signed: right after its element's `Issuer`
pub(crate) const SLOT: &str = "<!--SIG-->";

/// `unsigned` with the first `element` signed (enveloped, exclusive C14N, RSA-SHA256) and the
/// `ds:Signature` where [`SLOT`] stands; with `cert_pem`, the certificate in its `KeyInfo`.
pub(crate) fn sign_enveloped(unsigned: &str, element: &str, key_pem: &str, cert_pem: Option<&str>) -> String {
    let signature = signature(unsigned, element, RSA_SHA256, &|bytes| rsa_sha256(key_pem, bytes), cert_pem);
    unsigned.replacen(SLOT, &signature, 1)
}

/// The `ds:Signature` of the first `element` of `unsigned`: its digest (SHA-256, the element as
/// it is without a signature - the slot is a comment, which C14N leaves out), and `SignedInfo`
/// signed by `sign` under the name `method`.
pub(crate) fn signature(unsigned: &str, element: &str, method: &str, sign: &dyn Fn(&[u8]) -> Vec<u8>, cert_pem: Option<&str>) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    let doc = c14n::parse(unsigned).expect("parse the unsigned document");
    let apex = doc
        .descendants(c14n::Doc::ROOT)
        .into_iter()
        .find(|&n| doc.element(n).is_some_and(|e| e.local == element))
        .unwrap_or_else(|| panic!("no {element} element"));
    let id = doc.attr(apex, "ID").expect("the element's ID").to_string();
    let digest = ring::digest::digest(&ring::digest::SHA256, c14n::exclusive(&doc, apex, None, &[]).as_bytes());
    let signed_info = format!(
        "<ds:SignedInfo xmlns:ds=\"{DS}\"><ds:CanonicalizationMethod Algorithm=\"{EXC}\"></ds:CanonicalizationMethod>\
         <ds:SignatureMethod Algorithm=\"{method}\"></ds:SignatureMethod>\
         <ds:Reference URI=\"#{id}\"><ds:Transforms>\
         <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>\
         <ds:Transform Algorithm=\"{EXC}\"></ds:Transform></ds:Transforms>\
         <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>\
         <ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>",
        b64.encode(digest.as_ref())
    );
    let si_doc = c14n::parse(&signed_info).expect("parse SignedInfo");
    let canonical = c14n::exclusive(&si_doc, c14n::Doc::ROOT, None, &[]);
    let key_info = cert_pem
        .map(|pem| format!("<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>", pem_body(pem)))
        .unwrap_or_default();
    format!(
        "<ds:Signature xmlns:ds=\"{DS}\">{}<ds:SignatureValue>{}</ds:SignatureValue>{key_info}</ds:Signature>",
        signed_info.replacen(&format!(" xmlns:ds=\"{DS}\""), "", 1),
        b64.encode(sign(canonical.as_bytes()))
    )
}

/// RSA PKCS#1 v1.5 over SHA-256, with a PKCS#8 PEM key
pub(crate) fn rsa_sha256(key_pem: &str, bytes: &[u8]) -> Vec<u8> {
    let der = base64::engine::general_purpose::STANDARD.decode(pem_body(key_pem)).expect("the key's base64");
    let key = ring::signature::RsaKeyPair::from_pkcs8(&der).expect("a PKCS#8 RSA key");
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(&ring::signature::RSA_PKCS1_SHA256, &ring::rand::SystemRandom::new(), bytes, &mut sig).expect("sign");
    sig
}

/// A PEM's base64, on one line
pub(crate) fn pem_body(pem: &str) -> String {
    pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect()
}
