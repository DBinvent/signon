//! A small XML tree and Exclusive XML Canonicalization 1.0 (without
//! comments) over it — exactly the part of XML-DSig a SAML signature needs,
//! and nothing else.
//!
//! Why hand-written: the host this ships on has no `xmlsec1` headers, so the
//! C-backed SAML crates cannot build. Why that is acceptable: the input is
//! narrowed hard before canonicalization ever runs —
//!
//! * any `DOCTYPE` (and with it every entity declaration) is refused, so the
//!   only references are the five predefined entities and character
//!   references;
//! * line endings and attribute values are normalised the way an XML 1.0
//!   parser must, *before* the tree is built, so the canonical form is computed
//!   from the same values the caller later reads;
//! * comments are dropped and the text around them merged into one node, so
//!   the text a caller reads is exactly the text that was signed — the
//!   `user@evil.com<!---->.victim.com` class of bug cannot happen here;
//! * size and depth are capped.
//!
//! The output is checked against libxml2's own exclusive C14N (via `lxml`) in
//! the tests.

use std::collections::BTreeMap;

use quick_xml::events::Event;

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const MAX_NODES: usize = 20_000;
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone)]
pub struct Attr {
    pub prefix: Option<String>,
    pub local: String,
    /// Resolved namespace URI; `None` for an unprefixed attribute.
    pub ns: Option<String>,
    /// After XML attribute-value normalisation and reference expansion.
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Element {
    pub prefix: Option<String>,
    pub local: String,
    pub ns: Option<String>,
    /// Namespace declarations written on this element: `(None, uri)` is
    /// `xmlns="uri"`, `(Some(p), uri)` is `xmlns:p="uri"`.
    pub ns_decls: Vec<(Option<String>, String)>,
    pub attrs: Vec<Attr>,
    pub children: Vec<usize>,
}

#[derive(Debug, Clone)]
pub enum NodeKind {
    Element(Element),
    Text(String),
    /// `(target, data)`.
    Pi(String, String),
}

#[derive(Debug, Clone)]
pub struct Node {
    pub parent: Option<usize>,
    pub kind: NodeKind,
}

/// A parsed document. Node 0 is the root element.
#[derive(Debug)]
pub struct Doc {
    pub nodes: Vec<Node>,
}

impl Doc {
    pub const ROOT: usize = 0;

    pub fn element(&self, id: usize) -> Option<&Element> {
        match &self.nodes.get(id)?.kind {
            NodeKind::Element(e) => Some(e),
            _ => None,
        }
    }

    /// Element children of `id` in the given namespace and local name.
    pub fn children_named<'a>(
        &'a self,
        id: usize,
        ns: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = usize> + 'a {
        self.element(id)
            .map(|e| e.children.as_slice())
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(move |&c| {
                self.element(c)
                    .is_some_and(|e| e.ns.as_deref() == Some(ns) && e.local == local)
            })
    }

    pub fn child_named(&self, id: usize, ns: &str, local: &str) -> Option<usize> {
        self.children_named(id, ns, local).next()
    }

    /// Every element in the subtree rooted at `id`, `id` included, in
    /// document order.
    pub fn descendants(&self, id: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![id];
        while let Some(n) = stack.pop() {
            if let Some(e) = self.element(n) {
                out.push(n);
                stack.extend(e.children.iter().rev().copied());
            }
        }
        out
    }

    /// Value of an unprefixed attribute.
    pub fn attr(&self, id: usize, local: &str) -> Option<&str> {
        self.element(id)?
            .attrs
            .iter()
            .find(|a| a.ns.is_none() && a.local == local)
            .map(|a| a.value.as_str())
    }

    /// Concatenated text of the element's direct text children.
    pub fn text(&self, id: usize) -> String {
        let Some(e) = self.element(id) else {
            return String::new();
        };
        e.children
            .iter()
            .filter_map(|&c| match &self.nodes[c].kind {
                NodeKind::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Whether `id` lies inside the subtree rooted at `ancestor` (inclusive).
    pub fn is_within(&self, mut id: usize, ancestor: usize) -> bool {
        loop {
            if id == ancestor {
                return true;
            }
            match self.nodes[id].parent {
                Some(p) => id = p,
                None => return false,
            }
        }
    }

    /// The namespace URI bound to `prefix` at element `id`, looking up the
    /// ancestor chain. `None` prefix is the default namespace.
    fn in_scope(&self, mut id: usize, prefix: Option<&str>) -> Option<String> {
        if prefix == Some("xml") {
            return Some(XML_NS.to_string());
        }
        loop {
            if let Some(e) = self.element(id) {
                if let Some((_, uri)) = e.ns_decls.iter().find(|(p, _)| p.as_deref() == prefix) {
                    // `xmlns=""` undeclares the default namespace.
                    return (!uri.is_empty()).then(|| uri.clone());
                }
            }
            id = self.nodes[id].parent?;
        }
    }
}

// ---- parsing ------------------------------------------------------------------

/// Parses `input` into a [`Doc`], refusing anything outside the narrow subset
/// described in the module doc.
pub fn parse(input: &str) -> anyhow::Result<Doc> {
    if input.contains("<!DOCTYPE") || input.contains("<!ENTITY") {
        anyhow::bail!("DOCTYPE / entity declarations are not accepted");
    }
    // XML 1.0 §2.11: a parser normalises every line ending to #xA first.
    let normalized = input.replace("\r\n", "\n").replace('\r', "\n");

    let mut reader = quick_xml::Reader::from_str(&normalized);
    let config = reader.config_mut();
    config.expand_empty_elements = true;
    config.check_end_names = true;
    config.trim_text(false);

    let mut doc = Doc { nodes: Vec::new() };
    let mut stack: Vec<usize> = Vec::new();
    let mut root_seen = false;

    loop {
        let event = reader.read_event()?;
        if doc.nodes.len() > MAX_NODES {
            anyhow::bail!("document too large");
        }
        match event {
            Event::Start(start) => {
                if stack.is_empty() && root_seen {
                    anyhow::bail!("more than one root element");
                }
                if stack.len() >= MAX_DEPTH {
                    anyhow::bail!("document too deeply nested");
                }
                let (prefix, local) = split_qname(std::str::from_utf8(start.name().as_ref())?)?;
                let mut ns_decls = Vec::new();
                let mut raw_attrs = Vec::new();
                for attr in start.attributes().with_checks(true) {
                    let attr = attr?;
                    let key = std::str::from_utf8(attr.key.as_ref())?.to_string();
                    let value = normalize_attr_value(std::str::from_utf8(&attr.value)?)?;
                    if key == "xmlns" {
                        ns_decls.push((None, value));
                    } else if let Some(p) = key.strip_prefix("xmlns:") {
                        if value.is_empty() {
                            anyhow::bail!("prefix undeclaration is not XML 1.0");
                        }
                        ns_decls.push((Some(p.to_string()), value));
                    } else {
                        raw_attrs.push((key, value));
                    }
                }
                let id = doc.nodes.len();
                doc.nodes.push(Node {
                    parent: stack.last().copied(),
                    kind: NodeKind::Element(Element {
                        prefix: prefix.clone(),
                        local,
                        ns: None,
                        ns_decls,
                        attrs: Vec::new(),
                        children: Vec::new(),
                    }),
                });
                // Resolve names now that this element's own declarations are
                // in place.
                let ns = match prefix.as_deref() {
                    Some(p) => Some(
                        doc.in_scope(id, Some(p))
                            .ok_or_else(|| anyhow::anyhow!("undeclared prefix {p}"))?,
                    ),
                    None => doc.in_scope(id, None),
                };
                let mut attrs = Vec::with_capacity(raw_attrs.len());
                for (key, value) in raw_attrs {
                    let (aprefix, alocal) = split_qname(&key)?;
                    let ans = match aprefix.as_deref() {
                        Some(p) => Some(
                            doc.in_scope(id, Some(p))
                                .ok_or_else(|| anyhow::anyhow!("undeclared prefix {p}"))?,
                        ),
                        None => None,
                    };
                    attrs.push(Attr {
                        prefix: aprefix,
                        local: alocal,
                        ns: ans,
                        value,
                    });
                }
                // Two attributes that differ only by prefix but resolve to
                // the same expanded name are a namespace-well-formedness
                // error.
                for (i, a) in attrs.iter().enumerate() {
                    if attrs[..i].iter().any(|b| b.ns == a.ns && b.local == a.local) {
                        anyhow::bail!("duplicate attribute {}", a.local);
                    }
                }
                if let NodeKind::Element(e) = &mut doc.nodes[id].kind {
                    e.ns = ns;
                    e.attrs = attrs;
                }
                if let Some(&parent) = stack.last() {
                    if let NodeKind::Element(p) = &mut doc.nodes[parent].kind {
                        p.children.push(id);
                    }
                }
                stack.push(id);
                root_seen = true;
            }
            Event::End(_) => {
                stack.pop();
            }
            Event::Text(text) => {
                let raw = std::str::from_utf8(&text)?;
                push_text(&mut doc, &stack, raw)?;
            }
            Event::GeneralRef(reference) => {
                let resolved = if reference.is_char_ref() {
                    reference
                        .resolve_char_ref()?
                        .ok_or_else(|| anyhow::anyhow!("bad character reference"))?
                        .to_string()
                } else {
                    predefined_entity(std::str::from_utf8(&reference)?)?.to_string()
                };
                push_text(&mut doc, &stack, &resolved)?;
            }
            Event::CData(cdata) => {
                let raw = std::str::from_utf8(&cdata)?;
                push_text(&mut doc, &stack, raw)?;
            }
            Event::PI(pi) => {
                if let Some(&parent) = stack.last() {
                    let target = std::str::from_utf8(pi.target())?.to_string();
                    let content = std::str::from_utf8(pi.content())?.trim_start().to_string();
                    let id = doc.nodes.len();
                    doc.nodes.push(Node {
                        parent: Some(parent),
                        kind: NodeKind::Pi(target, content),
                    });
                    if let NodeKind::Element(p) = &mut doc.nodes[parent].kind {
                        p.children.push(id);
                    }
                }
            }
            Event::Comment(_) | Event::Decl(_) => {}
            Event::DocType(_) => anyhow::bail!("DOCTYPE is not accepted"),
            Event::Empty(_) => unreachable!("expand_empty_elements is on"),
            Event::Eof => break,
        }
    }
    if !root_seen || !stack.is_empty() {
        anyhow::bail!("not a complete XML document");
    }
    Ok(doc)
}

/// Appends text to the current element, merging with a preceding text node
/// — so a comment (dropped) between two runs of text leaves one node, and
/// what a caller reads is what was signed.
fn push_text(doc: &mut Doc, stack: &[usize], text: &str) -> anyhow::Result<()> {
    let Some(&parent) = stack.last() else {
        // Whitespace outside the root is not part of the document.
        if text.trim().is_empty() {
            return Ok(());
        }
        anyhow::bail!("text outside the root element");
    };
    let last = match &doc.nodes[parent].kind {
        NodeKind::Element(e) => e.children.last().copied(),
        _ => None,
    };
    if let Some(last) = last {
        if let NodeKind::Text(existing) = &mut doc.nodes[last].kind {
            existing.push_str(text);
            return Ok(());
        }
    }
    let id = doc.nodes.len();
    doc.nodes.push(Node {
        parent: Some(parent),
        kind: NodeKind::Text(text.to_string()),
    });
    if let NodeKind::Element(p) = &mut doc.nodes[parent].kind {
        p.children.push(id);
    }
    Ok(())
}

fn split_qname(qname: &str) -> anyhow::Result<(Option<String>, String)> {
    match qname.split_once(':') {
        Some((p, l)) if !p.is_empty() && !l.is_empty() && !l.contains(':') => {
            Ok((Some(p.to_string()), l.to_string()))
        }
        Some(_) => anyhow::bail!("malformed name {qname}"),
        None if !qname.is_empty() => Ok((None, qname.to_string())),
        None => anyhow::bail!("empty name"),
    }
}

fn predefined_entity(name: &str) -> anyhow::Result<char> {
    Ok(match name {
        "lt" => '<',
        "gt" => '>',
        "amp" => '&',
        "apos" => '\'',
        "quot" => '"',
        other => anyhow::bail!("undefined entity &{other};"),
    })
}

/// XML 1.0 §3.3.3 for CDATA-typed attributes (no DTD means every attribute
/// is CDATA): literal whitespace becomes a space, references are expanded.
/// A space produced by `&#xA;` stays a newline — that is the difference the
/// spec draws, and the canonical form depends on it.
fn normalize_attr_value(raw: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '&' => {
                let rest = &raw[i + 1..];
                let end = rest
                    .find(';')
                    .ok_or_else(|| anyhow::anyhow!("unterminated reference"))?;
                let name = &rest[..end];
                let ch = if let Some(hex) = name.strip_prefix("#x") {
                    char::from_u32(u32::from_str_radix(hex, 16)?)
                        .ok_or_else(|| anyhow::anyhow!("bad character reference"))?
                } else if let Some(dec) = name.strip_prefix('#') {
                    char::from_u32(dec.parse::<u32>()?)
                        .ok_or_else(|| anyhow::anyhow!("bad character reference"))?
                } else {
                    predefined_entity(name)?
                };
                out.push(ch);
                // Skip past the `;`.
                for _ in 0..name.chars().count() + 1 {
                    chars.next();
                }
            }
            '<' => anyhow::bail!("'<' in an attribute value"),
            '\t' | '\n' | '\r' => out.push(' '),
            other => out.push(other),
        }
    }
    Ok(out)
}

// ---- canonicalization --------------------------------------------------------

/// Exclusive C14N 1.0, without comments, of the subtree at `apex`, leaving
/// out the subtree at `exclude` (the enveloped `Signature`, when there is
/// one). `inclusive_prefixes` is the `InclusiveNamespaces PrefixList`;
/// `#default` names the default namespace.
pub fn exclusive(doc: &Doc, apex: usize, exclude: Option<usize>, inclusive_prefixes: &[String]) -> String {
    let mut out = String::new();
    let rendered: BTreeMap<Option<String>, String> = BTreeMap::new();
    write_node(doc, apex, exclude, inclusive_prefixes, &rendered, &mut out);
    out
}

fn write_node(
    doc: &Doc,
    id: usize,
    exclude: Option<usize>,
    inclusive: &[String],
    rendered: &BTreeMap<Option<String>, String>,
    out: &mut String,
) {
    if Some(id) == exclude {
        return;
    }
    match &doc.nodes[id].kind {
        NodeKind::Text(t) => escape_text(t, out),
        NodeKind::Pi(target, data) => {
            out.push_str("<?");
            out.push_str(target);
            if !data.is_empty() {
                out.push(' ');
                out.push_str(data);
            }
            out.push_str("?>");
        }
        NodeKind::Element(e) => {
            // Which prefixes this element needs declared: its own, its
            // prefixed attributes', and any the PrefixList asks for.
            let mut wanted: Vec<Option<String>> = vec![e.prefix.clone()];
            for a in &e.attrs {
                if a.prefix.is_some() {
                    wanted.push(a.prefix.clone());
                }
            }
            for p in inclusive {
                let p = if p == "#default" { None } else { Some(p.clone()) };
                // A PrefixList entry is rendered only if it is actually in
                // scope here.
                if doc.in_scope(id, p.as_deref()).is_some() || p.is_none() {
                    wanted.push(p);
                }
            }

            let mut decls: BTreeMap<Option<String>, String> = BTreeMap::new();
            for p in wanted {
                if p.as_deref() == Some("xml") || decls.contains_key(&p) {
                    continue;
                }
                let uri = doc.in_scope(id, p.as_deref()).unwrap_or_default();
                let already = rendered.get(&p).cloned().unwrap_or_default();
                // Output a declaration only when it changes what an output
                // ancestor already said. For the default namespace that
                // includes `xmlns=""` undoing an ancestor's default.
                if uri != already {
                    decls.insert(p, uri);
                }
            }

            out.push('<');
            push_qname(e.prefix.as_deref(), &e.local, out);
            // BTreeMap order: `None` (default) first, then prefixes sorted.
            for (p, uri) in &decls {
                match p {
                    None => out.push_str(" xmlns=\""),
                    Some(p) => {
                        out.push_str(" xmlns:");
                        out.push_str(p);
                        out.push_str("=\"");
                    }
                }
                escape_attr(uri, out);
                out.push('"');
            }
            let mut attrs: Vec<&Attr> = e.attrs.iter().collect();
            attrs.sort_by(|a, b| {
                (a.ns.as_deref().unwrap_or(""), a.local.as_str())
                    .cmp(&(b.ns.as_deref().unwrap_or(""), b.local.as_str()))
            });
            for a in attrs {
                out.push(' ');
                push_qname(a.prefix.as_deref(), &a.local, out);
                out.push_str("=\"");
                escape_attr(&a.value, out);
                out.push('"');
            }
            out.push('>');

            let mut child_rendered = rendered.clone();
            for (p, uri) in decls {
                child_rendered.insert(p, uri);
            }
            for &c in &e.children {
                write_node(doc, c, exclude, inclusive, &child_rendered, out);
            }
            out.push_str("</");
            push_qname(e.prefix.as_deref(), &e.local, out);
            out.push('>');
        }
    }
}

fn push_qname(prefix: Option<&str>, local: &str, out: &mut String) {
    if let Some(p) = prefix {
        out.push_str(p);
        out.push(':');
    }
    out.push_str(local);
}

fn escape_text(t: &str, out: &mut String) {
    for c in t.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

fn escape_attr(v: &str, out: &mut String) {
    for c in v.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(input, apex local name, PrefixList, expected)`. Expected values were
    /// produced by libxml2 through
    /// `lxml.etree.tostring(el, method="c14n", exclusive=True,
    /// with_comments=False, inclusive_ns_prefixes=[...])` — an independent
    /// implementation, so these are not just this code agreeing with itself.
    const CASES: &str = include_str!("../tests/fixtures/c14n_cases.json");

    #[derive(serde::Deserialize)]
    struct Case {
        name: String,
        input: String,
        apex: String,
        prefixes: Vec<String>,
        expected: String,
    }

    #[test]
    fn matches_libxml2_exclusive_c14n() {
        let cases: Vec<Case> = serde_json::from_str(CASES).unwrap();
        assert!(cases.len() >= 8);
        for case in cases {
            let doc = parse(&case.input).unwrap_or_else(|e| panic!("{}: {e}", case.name));
            let apex = (0..doc.nodes.len())
                .find(|&i| doc.element(i).is_some_and(|e| e.local == case.apex))
                .unwrap_or_else(|| panic!("{}: no {}", case.name, case.apex));
            let got = exclusive(&doc, apex, None, &case.prefixes);
            assert_eq!(got, case.expected, "case {}", case.name);
        }
    }

    #[test]
    fn doctype_and_entities_are_refused() {
        assert!(parse("<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>").is_err());
        assert!(parse("<a>&nbsp;</a>").is_err());
    }

    #[test]
    fn a_comment_does_not_split_text() {
        let doc = parse("<a>user@evil.com<!---->.victim.com</a>").unwrap();
        assert_eq!(doc.text(Doc::ROOT), "user@evil.com.victim.com");
    }

    #[test]
    fn undeclared_prefixes_and_duplicate_expanded_attributes_are_refused() {
        assert!(parse("<p:a/>").is_err());
        assert!(parse(r#"<a xmlns:x="u" xmlns:y="u" x:b="1" y:b="2"/>"#).is_err());
    }

    #[test]
    fn excluded_subtree_is_left_out() {
        let doc = parse(r#"<a ID="1"><Sig>x</Sig><b>y</b></a>"#).unwrap();
        let sig = doc.descendants(Doc::ROOT)[1];
        assert_eq!(exclusive(&doc, Doc::ROOT, Some(sig), &[]), r#"<a ID="1"><b>y</b></a>"#);
    }
}
