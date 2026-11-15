//! The messengers this build has a template for (feature `notify-templates`): each a request -
//! where it goes, its headers, its body - with places a message and the site's own settings fill.
//!
//! The templates are set when the crate is built, not when it runs. `build.rs` reads them from a
//! TOML file - the crate's `notify-templates.toml`, or the one `SIGNON_NOTIFY_TEMPLATES` names at
//! build time - checks them, and writes them out as the `static` included below. That file says
//! what a template may hold. At run time a site gives only a template's params: its address, its
//! token ([`super::Channel::Template`], `NOTIFY_<TEMPLATE>_<PARAM>`).

use serde_json::Value;

use super::{Level, Message};

/// One messenger, as the build wrote it
pub struct Template {
    pub name: &'static str,
    /// What a site sets for it, in the file's order
    pub params: &'static [&'static str],
    pub(super) method: Method,
    pub(super) url: &'static str,
    pub(super) headers: &'static [(&'static str, &'static str)],
    pub(super) basic_auth: Option<(&'static str, &'static str)>,
    pub(super) body: Body,
    pub(super) max_chars: usize,
    pub(super) max_title: usize,
    /// a link whose address is longer is left out
    pub(super) max_link: usize,
    /// what `{level}` reads for info, warning, severe
    pub(super) levels: [&'static str; 3],
    /// a field of the service's JSON answer, and the value that says it took the message
    pub(super) ok: Option<(&'static str, &'static str)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Method {
    Post,
    Put,
}

pub(super) enum Body {
    Json(J),
    Form(&'static [(&'static str, &'static str)]),
}

/// A JSON body as the file gave it; its strings are filled when it is sent
#[allow(dead_code)] // which of these a build holds is its template file's matter
pub(super) enum J {
    Bool(bool),
    /// a number, as it was written
    Num(&'static str),
    Str(&'static str),
    Arr(&'static [J]),
    Obj(&'static [(&'static str, J)]),
}

include!(concat!(env!("OUT_DIR"), "/notify_templates.rs"));

/// Every template of this build
pub fn all() -> &'static [Template] {
    TEMPLATES
}

/// The template of that name
pub fn find(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// Why a site's params do not make a request of a template
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NotMade {
    /// a param of the template the site did not give
    Missing(String),
    /// [review 2026-11-15] a param given that the template has not, or given twice: a name
    /// mistyped went unnoticed, and of two values the first was used
    NotOne(String),
}

/// [review 2026-11-15] `s` in at most `max` characters, the `...` that says it was cut among
/// them. A template's limit is its service's: one character over is a message refused.
fn cut_to(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(3)).collect();
    format!("{kept}{}", &"..."[..max.min(3)])
}

/// The request one message makes of one template
pub(super) struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub basic_auth: Option<(String, String)>,
    pub body: Payload,
    pub ok: Option<(&'static str, &'static str)>,
}

pub(super) enum Payload {
    Json(Value),
    Form(Vec<(String, String)>),
}

/// `template` with each `{name}` put as `value` answers for it; `{{` and `}}` are braces. The
/// build checked every name, so one with no value here is a param the site did not give: it is
/// the error.
fn fill(template: &str, value: &mut dyn FnMut(&str, usize) -> Option<String>) -> Result<String, String> {
    let (mut out, mut rest, mut at_start) = (String::with_capacity(template.len() + 32), template, true);
    while let Some(at) = rest.find(['{', '}']) {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        if rest[at..].starts_with("{{") || rest[at..].starts_with("}}") {
            out.push_str(&rest[at..at + 1]);
            rest = &after[1..];
        } else {
            let end = after.find('}').unwrap_or(after.len());
            let name = &after[..end];
            let place = if at_start && at == 0 { 0 } else { 1 };
            out.push_str(&value(name, place).ok_or_else(|| name.to_string())?);
            rest = after.get(end + 1..).unwrap_or_default();
        }
        at_start = false;
    }
    out.push_str(rest);
    Ok(out)
}

impl Template {
    /// The request `message` makes of this template with a site's `params`: each of the
    /// template's params once, and no other.
    pub(super) fn request(&self, params: &[(String, String)], message: &Message) -> Result<Request, NotMade> {
        for (i, (given, _)) in params.iter().enumerate() {
            if !self.params.contains(&given.as_str()) || params[..i].iter().any(|(earlier, _)| earlier == given) {
                return Err(NotMade::NotOne(given.clone()));
            }
        }
        self.filled(params, message).map_err(NotMade::Missing)
    }

    fn filled(&self, params: &[(String, String)], message: &Message) -> Result<Request, String> {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let level = self.levels[match message.level {
            Level::Info => 0,
            Level::Warning => 1,
            Level::Severe => 2,
        }];
        let link = message.web_link().filter(|(_, url)| url.chars().count() <= self.max_link);
        let known = |name: &str| -> Option<String> {
            Some(match name {
                // the level's word ahead of the title is within the title's limit
                "title" => cut_to(&format!("{}{}", message.level.tag(), message.title), self.max_title),
                "text" => cut_to(&message.text, self.max_chars),
                "level" => level.to_string(),
                "link_url" => link.as_ref().map(|(_, url)| url.to_string()).unwrap_or_default(),
                "link_label" => link.as_ref().map(|(label, _)| label.clone()).unwrap_or_default(),
                "unique" => unique.clone(),
                param => params.iter().find(|(p, _)| p == param).map(|(_, v)| v.clone())?,
            })
        };
        let mut as_it_is = |name: &str, _: usize| known(name);
        // in an address a value is one part of a path or of a query, percent-encoded - but the
        // param the address starts with, which is an address itself
        let mut in_url = |name: &str, place: usize| {
            let value = known(name)?;
            Some(if place == 0 { value.trim_end_matches('/').to_string() } else { urlencoding::encode(&value).into_owned() })
        };
        let url = fill(self.url, &mut in_url)?;
        let headers = self.headers.iter().map(|(h, v)| Ok((h.to_string(), fill(v, &mut as_it_is)?))).collect::<Result<_, String>>()?;
        let basic_auth = match self.basic_auth {
            Some((user, password)) => Some((fill(user, &mut as_it_is)?, fill(password, &mut as_it_is)?)),
            None => None,
        };
        let body = match &self.body {
            Body::Json(tree) => Payload::Json(json(tree, &mut as_it_is)?),
            Body::Form(fields) => {
                Payload::Form(fields.iter().map(|(f, v)| Ok((f.to_string(), fill(v, &mut as_it_is)?))).collect::<Result<_, String>>()?)
            }
        };
        Ok(Request { method: self.method, url, headers, basic_auth, body, ok: self.ok })
    }
}

/// The tree as JSON, its strings filled. A value goes into a string as it is: what makes it
/// safe in JSON is the serializer, when the body is sent.
fn json(tree: &J, value: &mut dyn FnMut(&str, usize) -> Option<String>) -> Result<Value, String> {
    Ok(match tree {
        J::Bool(b) => Value::Bool(*b),
        J::Num(n) => n.parse::<i64>().map(Value::from).or_else(|_| n.parse::<f64>().map(Value::from)).unwrap_or(Value::Null),
        J::Str(s) => Value::String(fill(s, value)?),
        J::Arr(items) => Value::Array(items.iter().map(|i| json(i, value)).collect::<Result<_, _>>()?),
        J::Obj(fields) => {
            Value::Object(fields.iter().map(|(k, v)| Ok((k.to_string(), json(v, value)?))).collect::<Result<_, String>>()?)
        }
    })
}
