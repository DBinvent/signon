//! [notify-templates] The messengers a build of signon can send to, from a TOML file to Rust.
//!
//! The file is read when the crate is built and at no other time: `SIGNON_NOTIFY_TEMPLATES` names
//! it, else it is the crate's own `notify-templates.toml`, which also says what a template may
//! hold. Everything is checked here - a key that is not known, a `{name}` that is no keyword and
//! no param, a param nothing uses - and a file that is wrong stops the build with its place. What
//! comes out is a `static` the crate includes (`src/notify/template.rs`): no file is read, and no
//! TOML parsed, when the crate runs.
//!
//! build.rs runs this; the crate's tests include the same file to test it.
#![allow(dead_code)] // `run` is the build script's, the rest the tests' too

use std::collections::BTreeSet;
use std::fmt::Write as _;

/// What a template can ask to have filled in, beside its own params
pub const KEYWORDS: &[&str] = &["title", "text", "level", "link_url", "link_label", "unique"];
/// The channels the crate has code for: a template is not named as one of them
const BUILT_IN: &[&str] = &["slack", "teams", "telegram", "webhook", "email", "template"];
const KEYS: &[&str] = &["params", "url", "method", "headers", "basic_auth", "json", "form", "max_chars", "max_title", "max_link",
    "levels", "ok_field", "ok_value"];
/// The settings the crate's own channels are read from: no template's param is read from one
const OWN_SETTINGS: &[&str] = &["NOTIFY_TO", "NOTIFY_SLACK_WEBHOOK", "NOTIFY_TEAMS_WEBHOOK", "NOTIFY_TELEGRAM_TOKEN", "NOTIFY_TELEGRAM_CHAT",
    "NOTIFY_WEBHOOK_URL", "NOTIFY_WEBHOOK_BEARER", "NOTIFY_EMAIL_TO"];
const LEVELS: &[&str] = &["info", "warning", "severe"];

/// The build script's part: the file to `OUT_DIR/notify_templates.rs`, or the build's end
pub fn run() {
    let own = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR")).join("notify-templates.toml");
    let file = match std::env::var("SIGNON_NOTIFY_TEMPLATES") {
        Ok(path) if !path.trim().is_empty() => std::path::PathBuf::from(path.trim()),
        _ => own,
    };
    println!("cargo:rerun-if-changed={}", file.display());
    let text = std::fs::read_to_string(&file)
        .unwrap_or_else(|e| panic!("notify templates: {} cannot be read: {e}", file.display()));
    let rust = generate(&text).unwrap_or_else(|e| panic!("notify templates: {}: {e}", file.display()));
    let out = std::path::Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("notify_templates.rs");
    std::fs::write(&out, rust).unwrap_or_else(|e| panic!("notify templates: {} cannot be written: {e}", out.display()));
}

/// The file's templates as Rust: `pub static TEMPLATES: &[Template] = &[...];`, in the file's
/// order of names. An error names the template and what is wrong with it.
pub fn generate(text: &str) -> Result<String, String> {
    let file: toml::Table = text.parse().map_err(|e| format!("not TOML: {e}"))?;
    let mut out = String::from("pub static TEMPLATES: &[Template] = &[\n");
    // [review 2026-11-15] two params of two templates read from one setting would get one value
    let mut settings: Vec<(String, String)> = OWN_SETTINGS.iter().map(|s| (s.to_string(), "the crate's own channel".to_string())).collect();
    for (name, value) in &file {
        let table = value.as_table().ok_or_else(|| format!("{name}: a template is a table, [{name}]"))?;
        let params = template(name, table, &mut out).map_err(|e| format!("[{name}]: {e}"))?;
        for param in params {
            let setting = format!("NOTIFY_{}_{}", name.to_uppercase(), param.to_uppercase());
            if let Some((_, other)) = settings.iter().find(|(s, _)| *s == setting) {
                return Err(format!("[{name}]: its param {param} is read from {setting}, as is {other}"));
            }
            settings.push((setting, format!("the param {param} of [{name}]")));
        }
    }
    out.push_str("];\n");
    Ok(out)
}

/// a template's name, a param's name: lower-case letters, digits and `_`, a letter first
fn is_name(s: &str) -> bool {
    s.len() <= 32
        && s.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The `{name}`s of a string, in order; `{{` and `}}` are braces. A brace that opens no name, or
/// closes none, is an error: it would be sent as it stands.
pub fn names(text: &str) -> Result<Vec<String>, String> {
    let (mut out, mut rest) = (Vec::new(), text);
    while let Some(at) = rest.find(['{', '}']) {
        let after = &rest[at + 1..];
        if rest[at..].starts_with("{{") || rest[at..].starts_with("}}") {
            rest = &after[1..];
        } else if rest.as_bytes()[at] == b'}' {
            return Err(format!("a `}}` that closes nothing in {text:?} (write `}}}}` for a brace)"));
        } else {
            let end = after.find('}').ok_or_else(|| format!("a `{{` that is not closed in {text:?} (write `{{{{` for a brace)"))?;
            let name = &after[..end];
            if !is_name(name) {
                return Err(format!("{{{name}}} in {text:?} is no name"));
            }
            out.push(name.to_string());
            rest = &after[end + 1..];
        }
    }
    Ok(out)
}

/// what one template's strings may name, and what of its params they did
struct Uses<'a> {
    params: &'a [String],
    used: BTreeSet<String>,
}

impl Uses<'_> {
    /// `text` checked: every `{name}` in it a keyword or a param
    fn of(&mut self, text: &str) -> Result<(), String> {
        for name in names(text)? {
            if self.params.contains(&name) {
                self.used.insert(name);
            } else if !KEYWORDS.contains(&name.as_str()) {
                return Err(format!("{{{name}}} is no keyword ({}) and no param of this template", KEYWORDS.join(", ")));
            }
        }
        Ok(())
    }
}

fn string<'a>(table: &'a toml::Table, key: &str) -> Result<Option<&'a str>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(toml::Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(format!("{key} is a string")),
    }
}

fn count(table: &toml::Table, key: &str, default: i64, most: i64) -> Result<i64, String> {
    match table.get(key) {
        None => Ok(default),
        Some(toml::Value::Integer(n)) if (1..=most).contains(n) => Ok(*n),
        Some(_) => Err(format!("{key} is a number from 1 to {most}")),
    }
}

/// One template written to `out`; its params, for the settings they are read from
fn template(name: &str, t: &toml::Table, out: &mut String) -> Result<Vec<String>, String> {
    if !is_name(name) {
        return Err("a template's name is lower-case letters, digits and `_`, a letter first, 32 at most".into());
    }
    if BUILT_IN.contains(&name) {
        return Err("that is the name of a channel the crate has itself".into());
    }
    if let Some(unknown) = t.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(format!("{unknown} is no key of a template ({})", KEYS.join(", ")));
    }

    let params: Vec<String> = match t.get("params") {
        Some(toml::Value::Array(list)) if !list.is_empty() && list.len() <= 8 => list
            .iter()
            .map(|p| p.as_str().filter(|p| is_name(p)).map(str::to_string).ok_or_else(|| "a param is a name: lower-case letters, digits and `_`".to_string()))
            .collect::<Result<_, _>>()?,
        _ => return Err("params is a list of one to eight names".into()),
    };
    for (i, p) in params.iter().enumerate() {
        if KEYWORDS.contains(&p.as_str()) {
            return Err(format!("the param {p} has a keyword's name"));
        }
        if params[..i].contains(p) {
            return Err(format!("the param {p} is there twice"));
        }
    }
    let mut uses = Uses { params: &params, used: BTreeSet::new() };

    let url = string(t, "url")?.ok_or("url is missing")?;
    uses.of(url)?;
    let whole = params.iter().any(|p| url.starts_with(&format!("{{{p}}}")));
    if !(url.starts_with("https://") || url.starts_with("http://") || whole) {
        return Err("url starts with https://, or with a param that holds the address".into());
    }
    let method = match string(t, "method")?.unwrap_or("POST") {
        "POST" => "Post",
        "PUT" => "Put",
        other => return Err(format!("method is POST or PUT, not {other}")),
    };

    let mut headers = Vec::new();
    match t.get("headers") {
        None => {}
        Some(toml::Value::Table(h)) => {
            for (header, value) in h {
                if header.is_empty() || !header.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err(format!("{header:?} is no header's name"));
                }
                let value = value.as_str().ok_or_else(|| format!("the header {header} is a string"))?;
                uses.of(value)?;
                headers.push((header.clone(), value.to_string()));
            }
        }
        Some(_) => return Err("headers is a table of header = value".into()),
    }
    let basic = match t.get("basic_auth") {
        None => None,
        Some(toml::Value::Array(pair)) if pair.len() == 2 && pair.iter().all(toml::Value::is_str) => {
            let (user, password) = (pair[0].as_str().unwrap_or_default(), pair[1].as_str().unwrap_or_default());
            uses.of(user)?;
            uses.of(password)?;
            Some((user.to_string(), password.to_string()))
        }
        Some(_) => return Err("basic_auth is [user, password]".into()),
    };

    let body = match (t.get("json"), t.get("form")) {
        (Some(toml::Value::Table(json)), None) => format!("Body::Json({})", json_tree(&toml::Value::Table(json.clone()), &mut uses)?),
        (None, Some(toml::Value::Table(form))) => {
            let mut fields = String::new();
            for (field, value) in form {
                let value = value.as_str().ok_or_else(|| format!("the form field {field} is a string"))?;
                uses.of(value)?;
                write!(fields, "({field:?}, {value:?}), ").expect("a String");
            }
            format!("Body::Form(&[{fields}])")
        }
        (Some(_), Some(_)) => return Err("a template has json or form, not both".into()),
        (None, None) => return Err("a template has a body: a json table or a form table".into()),
        _ => return Err("json and form are tables".into()),
    };

    let max_chars = count(t, "max_chars", 3500, 100_000)?;
    let max_title = count(t, "max_title", 200, 1000)?;
    let max_link = count(t, "max_link", 1000, 1000)?;
    let mut levels = [LEVELS[0].to_string(), LEVELS[1].to_string(), LEVELS[2].to_string()];
    match t.get("levels") {
        None => {}
        Some(toml::Value::Table(given)) => {
            for (level, word) in given {
                let at = LEVELS.iter().position(|l| l == level).ok_or_else(|| format!("{level} is no level ({})", LEVELS.join(", ")))?;
                let word = word.as_str().ok_or_else(|| format!("the level {level} is a string"))?;
                // [review 2026-11-15] a level's word is sent as it is: nothing in it is filled
                if word.contains(['{', '}']) {
                    return Err(format!("the level {level} is a plain word: {word:?} has a brace, and nothing in a level is filled"));
                }
                levels[at] = word.to_string();
            }
        }
        Some(_) => return Err("levels is a table: info, warning, severe".into()),
    }
    let ok = match (string(t, "ok_field")?, t.get("ok_value")) {
        (None, None) => None,
        (Some(field), Some(value)) if !field.is_empty() => Some((field.to_string(), match value {
            toml::Value::String(s) => s.clone(),
            toml::Value::Integer(n) => n.to_string(),
            toml::Value::Boolean(b) => b.to_string(),
            _ => return Err("ok_value is a string, a whole number or true / false".into()),
        })),
        _ => return Err("ok_field and ok_value go together".into()),
    };

    if let Some(idle) = params.iter().find(|p| !uses.used.contains(*p)) {
        return Err(format!("the param {idle} is used nowhere"));
    }

    let headers: String = headers.iter().map(|(h, v)| format!("({h:?}, {v:?}), ")).collect();
    writeln!(
        out,
        "    Template {{ name: {name:?}, params: &{params:?}, method: Method::{method}, url: {url:?}, headers: &[{headers}], \
         basic_auth: {basic:?}, body: {body}, max_chars: {max_chars}, max_title: {max_title}, max_link: {max_link}, \
         levels: {levels:?}, ok: {ok:?} }},"
    )
    .expect("a String");
    Ok(params)
}

/// A TOML value as the crate's JSON tree (`J`), its strings checked
fn json_tree(value: &toml::Value, uses: &mut Uses<'_>) -> Result<String, String> {
    Ok(match value {
        toml::Value::String(s) => {
            uses.of(s)?;
            format!("J::Str({s:?})")
        }
        toml::Value::Integer(n) => format!("J::Num({:?})", n.to_string()),
        // [review 2026-11-15] as it was written: 1.0 stays 1.0, not 1
        toml::Value::Float(f) if f.is_finite() => format!("J::Num({:?})", format!("{f:?}")),
        toml::Value::Boolean(b) => format!("J::Bool({b})"),
        toml::Value::Array(items) => {
            let items = items.iter().map(|i| json_tree(i, uses)).collect::<Result<Vec<_>, _>>()?;
            format!("J::Arr(&[{}])", items.join(", "))
        }
        toml::Value::Table(fields) => {
            let fields = fields.iter().map(|(k, v)| Ok(format!("({k:?}, {})", json_tree(v, uses)?))).collect::<Result<Vec<_>, String>>()?;
            format!("J::Obj(&[{}])", fields.join(", "))
        }
        _ => return Err("a body holds strings, numbers, true / false, lists and tables".into()),
    })
}
