//! [i18n] The language of what this crate says to a person: the API's error texts and the mail it sends.
//!
//! The messages are in `locales/<lang>.yml`: English, and - written with the code, not reviewed by a native
//! speaker - Russian, French, German, Simplified Chinese and Japanese. An error's message starts with its
//! code, `SO-Ennn`, the same in every language; the API answers it as `{"error": <text>, "code": <code>}`,
//! so a client can act on the code whatever the language of the text.
//!
//! The language is a request's, not the process's - one service answers users of several at once:
//! - a request's `Accept-Language` picks the first of its languages there is, else the site's own
//!   (`Config::lang`, `APP_LANG`; English when not set). The routers of this crate do this themselves;
//! - a mail a request causes (a confirmation, a reset, a sign-in code) is in that request's language;
//! - a mail nobody's request causes - the owner's alert, an admin's catch-up run - is in the site's.
//!
//! Log lines stay English: they are the operator's, read next to the code.

use std::future::Future;

/// The languages there are messages in; the first is what a language without them falls back to
pub const LANGS: [&str; 6] = ["en", "ru", "fr", "de", "zh", "ja"];
pub const DEFAULT_LANG: &str = "en";

tokio::task_local! {
    /// the language of the request this task serves (`scope`)
    static REQUEST_LANG: &'static str;
}

/// The language of `tag`, when there are messages in it: `ru`, `ru-RU`, `ru_RU.UTF-8` and `RU` are `ru`,
/// `zh-Hans-CN` is `zh`. None for any other, and for `*`. [review 2026-11-14] The Chinese here is the
/// Simplified one: a tag that asks for Traditional (`zh-TW`, `zh-HK`, `zh-MO`, `zh-Hant`) is not it.
pub fn supported(tag: &str) -> Option<&'static str> {
    let tag = tag.trim().to_ascii_lowercase();
    let mut parts = tag.split(['-', '_', '.', '@']);
    let language = parts.next().unwrap_or("");
    if language == "zh" && parts.any(|p| matches!(p, "hant" | "tw" | "hk" | "mo")) {
        return None;
    }
    LANGS.iter().copied().find(|l| *l == language)
}

/// `supported`, or English
pub fn language(tag: &str) -> &'static str {
    supported(tag).unwrap_or(DEFAULT_LANG)
}

/// The language an `Accept-Language` header asks for first, of those there are: by its q values (a
/// language with q=0 is refused, one with none is 1), then by its order. None when it names none of ours.
pub fn from_accept_language(header: &str) -> Option<&'static str> {
    let mut wanted: Vec<(f32, usize, &'static str)> = Vec::new();
    for (place, part) in header.split(',').enumerate() {
        let mut pieces = part.split(';');
        let Some(lang) = pieces.next().and_then(supported) else { continue };
        // [review 2026-11-14] `q` in either case: a parameter's name is not case-sensitive (RFC 9110)
        let q = pieces
            .find_map(|p| {
                let p = p.trim();
                p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")).map(|v| v.trim().parse::<f32>().unwrap_or(0.0))
            })
            .filter(|q| q.is_finite())
            .unwrap_or(1.0);
        if q > 0.0 {
            wanted.push((q, place, lang));
        }
    }
    wanted.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal).then(a.1.cmp(&b.1)));
    wanted.first().map(|w| w.2)
}

/// The language of the request this code runs for; English outside one
pub fn current() -> &'static str {
    REQUEST_LANG.try_with(|l| *l).unwrap_or(DEFAULT_LANG)
}

/// Runs `future` as a request in `lang`: what it says through this module is in that language. A task it
/// spawns is no part of the request - hand it `current()` and give it a scope of its own.
pub async fn scope<F: Future>(lang: &'static str, future: F) -> F::Output {
    REQUEST_LANG.scope(lang, future).await
}

/// The message of `key` in `lang`, its `%{name}` places filled from `args`
pub fn text_in(lang: &str, key: &str, args: &[(&str, &str)]) -> String {
    fill(&rust_i18n::t!(key, locale = language(lang)), args)
}

/// `template` with each `%{name}` replaced by its value, in one pass. [review 2026-11-14] A value is never
/// read for places itself: an address or a product name that holds `%{code}` stays as it was written. A
/// place with no value stays too.
fn fill(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(at) = rest.find("%{") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 2..];
        match after.find('}').map(|end| (&after[..end], end)) {
            Some((name, end)) => {
                match args.iter().find(|(n, _)| *n == name) {
                    Some((_, value)) => out.push_str(value),
                    None => out.push_str(&rest[at..at + 2 + end + 1]),
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[at..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

/// `text_in` the language of the request
pub fn text(key: &str, args: &[(&str, &str)]) -> String {
    text_in(current(), key, args)
}

/// An error's message split at its code: `("SO-E001", "invalid credentials")`. A message with no code -
/// there is none among the errors, a test holds that - is all text.
pub fn error_in(lang: &str, key: &str, args: &[(&str, &str)]) -> (String, String) {
    let message = text_in(lang, key, args);
    match message.split_once(' ') {
        Some((code, rest)) if is_code(code) => (code.to_string(), rest.to_string()),
        _ => (String::new(), message),
    }
}

/// `SO-E` and three digits
pub fn is_code(s: &str) -> bool {
    s.len() == 7 && s.starts_with("SO-E") && s[4..].bytes().all(|b| b.is_ascii_digit())
}

/// The body of an API error in the request's language: `{"error": <text>, "code": <code>}`
pub fn error_body(key: &str, args: &[(&str, &str)]) -> serde_json::Value {
    let (code, text) = error_in(current(), key, args);
    serde_json::json!({ "error": text, "code": code })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// a locale file as it is written: its keys and values (one `key: "value"` a line)
    fn file(lang: &str) -> BTreeMap<String, String> {
        let path = format!("{}/locales/{lang}.yml", env!("CARGO_MANIFEST_DIR"));
        let mut out = BTreeMap::new();
        for line in std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}")).lines() {
            if line.starts_with('#') || line.trim().is_empty() || line.starts_with("_version") {
                continue;
            }
            let (key, value) = line.split_once(": ").unwrap_or_else(|| panic!("{lang}: {line}"));
            let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or_else(|| panic!("{lang}: {line}"));
            assert!(out.insert(key.to_string(), value.replace("\\\"", "\"")).is_none(), "{lang}: {key} twice");
        }
        out
    }

    fn places(text: &str) -> BTreeSet<String> {
        text.split("%{").skip(1).filter_map(|p| p.split('}').next()).map(str::to_string).collect()
    }

    /// every key is in every language, with the same places to fill; an error has its code, the same in
    /// every language and no other error's; nothing is written with a long dash
    #[test]
    fn every_language_has_every_message_with_the_same_code_and_places() {
        let english = file("en");
        assert!(english.len() > 60, "{} keys", english.len());
        let mut codes: BTreeMap<String, String> = BTreeMap::new();
        for (key, text) in &english {
            let code = text.split(' ').next().unwrap_or("");
            if key.starts_with("err-") {
                assert!(is_code(code), "{key}: an error starts with its code: {text}");
                assert!(codes.insert(code.to_string(), key.clone()).is_none(), "{code} is two errors'");
            } else {
                assert!(!is_code(code), "{key} is no error and has a code");
            }
        }
        for lang in LANGS {
            let messages = file(lang);
            assert_eq!(messages.keys().collect::<Vec<_>>(), english.keys().collect::<Vec<_>>(), "{lang}: the same keys");
            for (key, text) in &messages {
                let en = &english[key];
                // the same places to fill - but English's a/an (%{article}), which no other language has
                let mut needed = places(en);
                if lang != "en" {
                    needed.remove("article");
                }
                assert_eq!(places(text), needed, "{lang} {key}: the same places to fill");
                assert!(!text.trim().is_empty(), "{lang} {key}");
                assert!(!text.contains('\u{2014}') && !text.contains('\u{2013}'), "{lang} {key}: a long dash");
                if key.starts_with("err-") {
                    assert_eq!(text.split(' ').next(), en.split(' ').next(), "{lang} {key}: the same code");
                    assert!(text.len() > 8, "{lang} {key}: a text after the code");
                }
            }
        }
    }

    /// the compiled-in messages are the files': a key answers its text in each language, never its own name
    #[test]
    fn a_message_is_read_in_its_language() {
        assert_eq!(text_in("en", "err-credentials", &[]), "SO-E001 invalid credentials");
        assert_eq!(error_in("en", "err-credentials", &[]), ("SO-E001".to_string(), "invalid credentials".to_string()));
        assert_eq!(error_in("de", "err-credentials", &[]).0, "SO-E001");
        assert_ne!(error_in("de", "err-credentials", &[]).1, "invalid credentials");
        assert_eq!(text_in("xx", "err-credentials", &[]), "SO-E001 invalid credentials", "a language without messages is English");
        assert_eq!(text_in("en", "err-password-short", &[("min", "8")]), "SO-E022 password must be at least 8 characters");
        for lang in LANGS {
            for (key, _) in file("en") {
                let got = text_in(lang, &key, &[]);
                assert_eq!(got, file(lang)[&key], "{lang} {key}");
            }
        }
        assert!(is_code("SO-E001") && !is_code("SO-E01") && !is_code("SO-EABC") && !is_code("SG-E001"));
    }

    /// [review 2026-11-14] a value is put in as it is: what looks like a place inside it is not filled
    #[test]
    fn a_value_is_never_read_for_places() {
        assert_eq!(fill("%{a} and %{b}", &[("a", "%{b}"), ("b", "B")]), "%{b} and B");
        assert_eq!(fill("%{b} and %{a}", &[("a", "A"), ("b", "%{a}")]), "%{a} and A");
        assert_eq!(fill("no places", &[("a", "A")]), "no places");
        assert_eq!(fill("%{unknown} stays, %{a} goes", &[("a", "A")]), "%{unknown} stays, A goes");
        assert_eq!(fill("an open %{a", &[("a", "A")]), "an open %{a");
        assert_eq!(fill("%{a}%{a}", &[("a", "x")]), "xx");
        assert_eq!(fill("100%, %{a}", &[("a", "\u{436}")]), "100%, \u{436}");
        let alert = text_in("en", "mail-signup-intro", &[("email", "x%{product}@a.test"), ("product", "Demo")]);
        assert_eq!(alert, "x%{product}@a.test asked for Demo updates.");
    }

    #[test]
    fn a_language_tag_and_an_accept_language_header_are_read() {
        for (tag, lang) in [("ru", Some("ru")), ("ru-RU", Some("ru")), ("ru_RU.UTF-8", Some("ru")), ("ZH-Hans-CN", Some("zh")),
                            ("de", Some("de")), (" fr ", Some("fr")), ("ja-JP", Some("ja")), ("es", None), ("*", None), ("", None)] {
            assert_eq!(supported(tag), lang, "{tag}");
        }
        assert_eq!(language("es-ES"), "en");
        assert_eq!(from_accept_language("de-DE,de;q=0.9,en;q=0.8"), Some("de"));
        assert_eq!(from_accept_language("es-ES, ru;q=0.7, fr;q=0.9"), Some("fr"), "by q, of those there are");
        assert_eq!(from_accept_language("es, pt;q=0.9"), None);
        assert_eq!(from_accept_language("ja;q=0, zh"), Some("zh"), "q=0 is a refusal");
        assert_eq!(from_accept_language("en;q=0.5, ru;q=0.5"), Some("en"), "the first of equals");
        assert_eq!(from_accept_language("*"), None);
        assert_eq!(from_accept_language(""), None);
        assert_eq!(from_accept_language("ru;q=abc, de;q=0.1"), Some("de"), "a q that is no number is 0");
        // [review 2026-11-14] `Q` as `q`; a q that is no finite number is none
        assert_eq!(from_accept_language("en;Q=0.1, de;Q=0.9"), Some("de"));
        assert_eq!(from_accept_language("en;q=inf, de;q=0.9"), Some("en"), "inf is no weight: 1 by default, and first");
        // Traditional Chinese is not the Chinese there is: the next language, or none
        for tag in ["zh-TW", "zh-HK", "zh_MO", "zh-Hant", "zh-Hant-TW"] {
            assert_eq!(supported(tag), None, "{tag}");
        }
        for tag in ["zh", "zh-CN", "zh_CN", "zh-Hans", "zh-Hans-CN", "zh-SG"] {
            assert_eq!(supported(tag), Some("zh"), "{tag}");
        }
        assert_eq!(from_accept_language("zh-TW, ja;q=0.8"), Some("ja"));
        assert_eq!(from_accept_language("zh-TW"), None);
    }

    /// the language is the request's: inside a scope it is that one, outside English; an error body carries
    /// the code beside the text
    #[tokio::test]
    async fn the_language_is_the_requests() {
        assert_eq!(current(), "en");
        assert_eq!(error_body("err-forbidden", &[]), serde_json::json!({"error": "forbidden", "code": "SO-E005"}));
        let (lang, body) = scope("ru", async { (current(), error_body("err-forbidden", &[])) }).await;
        assert_eq!(lang, "ru");
        assert_eq!(body["code"], "SO-E005");
        assert_ne!(body["error"], "forbidden");
        assert_eq!(current(), "en", "the scope ended");
        // a spawned task is not the request
        let spawned = scope("de", async { tokio::spawn(async { current() }).await.unwrap() }).await;
        assert_eq!(spawned, "en");
    }
}
