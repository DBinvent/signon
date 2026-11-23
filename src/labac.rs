//! [labac] LABAC - Leveled Attribute-Based Access Control - on top of signon's roles
//! (feature `labac`, the tables in `schema_labac.yaml`).
//!
//! - **The subject.** Mapping rules (`labac_rules`) take what an IdP says of a person - a
//!   SAML attribute, an OIDC claim, a SCIM group - matched by name, prefix, regex (with
//!   captures) or id, and give an ABAC group, a label (`department = $1`) with a level, and
//!   optionally a ceiling and a PostgreSQL role (`pg_role`: the group role ytproxy logs in to
//!   a node as for the person). They run at each sign-in and each SCIM change
//!   ([`remap`]); the result is an account's subject (`labac_subjects`): its groups, labels,
//!   PostgreSQL roles (in rule order), ceiling and a
//!   version that any change bumps - and a bump is told to the embedder's [`SubjectHook`]
//!   (YT Cluster writes an etcd key ytproxy and yui watch). signon itself depends on no etcd.
//! - **The resources.** A resource has a kind, an id, a parent, labels and a private flag
//!   (`labac_resources`); an ACL entry gives an ABAC group - `*` any subject - a level on a
//!   resource, with a label condition and a shared flag (`labac_entries`) - or, with an account
//!   id, gives that one person a level, counted only while the person is in the entry's group;
//!   an action is a level per kind (`labac_actions`; else select 1,
//!   insert 2, update 3, soft_delete 4, delete 5, ddl 6).
//! - **OPA** ([`Opa`], feature `opa`): where an OPA server is configured for a kind, its
//!   answer is the level of the resources it names (it may raise or lower signon's own), the
//!   ceiling still caps it; cached per subject version.
//! - **The evaluator** ([`Acl`]): `level(subject, resource)` - the highest matching entry on
//!   the resource itself, or one shared down from a parent; a private resource takes only its
//!   own. 0 denies, the ceiling caps it, and [`Why`] says which entry gave it. `reach` - the
//!   ids allowed an action; `predicate` - a SQL fragment with its parameters, for ytproxy to
//!   rewrite a statement with.
//! - **The token** ([`issue`], [`current`]): a JWT carrying the subject's account and version,
//!   HS256 under a key the site holds; a token of an older version is stale at once.
//!
//! A label condition is `key` - the resource's label `key` is one the subject holds - or
//! `key=value` - the subject holds that label. An entry matched through a label of level L
//! gives at most L (a label of level 0 caps nothing).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// What an IdP says of a person: one value of one attribute, claim or group
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// `saml`, `oidc` or `scim`
    pub source: String,
    /// the attribute's or claim's name: `groups`, `department`, ...
    pub name: String,
    pub value: String,
    /// the group's id at the IdP, where it has one (SCIM)
    #[serde(default)]
    pub id: Option<String>,
}

impl Claim {
    pub fn new(source: &str, name: &str, value: &str) -> Claim {
        Claim { source: source.to_string(), name: name.to_string(), value: value.to_string(), id: None }
    }
}

/// [labac] What an OIDC id_token says: each of its `groups`, as claim `groups`
#[cfg(feature = "oauth")]
pub fn claims_of_oidc(c: &crate::jwt::IdClaims) -> Vec<Claim> {
    c.groups.iter().map(|g| Claim::new("oidc", "groups", g)).collect()
}

/// [labac] What a SAML assertion says: each attribute value, and the groups again as claim
/// `groups` whatever their attribute's name
#[cfg(feature = "saml")]
pub fn claims_of_saml(a: &crate::saml::Assertion) -> Vec<Claim> {
    let mut out: Vec<Claim> = a.attributes.iter().map(|(n, v)| Claim::new("saml", n, v)).collect();
    out.extend(a.groups.iter().map(|g| Claim::new("saml", "groups", g)));
    out
}

/// How a rule matches a claim
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    /// the value is the pattern
    Name,
    /// the value starts with the pattern; `$1` the rest
    Prefix,
    /// the pattern, a regex, matches the whole value; `$1`.. its captures
    Regex,
    /// the claim's id is the pattern
    Id,
}

impl MatchKind {
    pub fn parse(s: &str) -> Option<MatchKind> {
        match s {
            "name" => Some(MatchKind::Name),
            "prefix" => Some(MatchKind::Prefix),
            "regex" => Some(MatchKind::Regex),
            "id" => Some(MatchKind::Id),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MatchKind::Name => "name",
            MatchKind::Prefix => "prefix",
            MatchKind::Regex => "regex",
            MatchKind::Id => "id",
        }
    }
}

/// A mapping rule (`labac_rules`), applied in id order
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    /// `saml`, `oidc`, `scim`, or `*`: any
    pub source: String,
    /// the claim's name it reads
    pub claim: String,
    pub kind: MatchKind,
    pub pattern: String,
    /// the ABAC group it gives; `$0` the value, `$1`.. its captures
    #[serde(default)]
    pub group: Option<String>,
    /// a label it gives: its key and value, `$1`.. as above
    #[serde(default)]
    pub label_key: Option<String>,
    #[serde(default)]
    pub label_value: Option<String>,
    /// the label's level: an entry matched through it gives at most this; 0 no cap
    #[serde(default)]
    pub level: i16,
    /// no action level above it for the subject: it caps what the ACL entries give - never a named
    /// level (`level_name`), which is another scale
    #[serde(default)]
    pub ceiling: Option<i16>,
    /// [labac] the PostgreSQL group role it gives (`$1`.. as above): the role ytproxy logs in to
    /// a node as for the person
    #[serde(default)]
    pub pg_role: Option<String>,
    /// [levels] a named level it gives the person - `sal`, the security access level, or another
    /// name: the person reaches a row whose level of that name is the same or lower. Its value is a
    /// number, or `$1`.. a capture of the claim; of the rules that match, the highest counts
    #[serde(default)]
    pub level_name: Option<String>,
    #[serde(default)]
    pub level_value: Option<String>,
}

/// [levels] the name of the level a declaration does not name: the security access level
pub const SAL: &str = "sal";

/// [levels] a level's name: letters, digits and `_`
pub fn level_name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 63 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// [levels] A person's levels: its own rows (`labac_levels`) over what the rules gave, name by name
pub fn effective_levels(rules: &BTreeMap<String, i16>, person: &BTreeMap<String, i16>) -> BTreeMap<String, i16> {
    let mut out = rules.clone();
    for (n, l) in person {
        out.insert(n.clone(), *l);
    }
    out
}

/// [levels] The levels a call asks for, against the person's own: each from 0 to its own, never
/// above - the tops a token is minted with, or a session works at. An unknown name's own is 0.
pub fn asked_levels(own: &BTreeMap<String, i16>, asked: &[(String, i16)]) -> Result<BTreeMap<String, i16>, String> {
    let mut caps = BTreeMap::new();
    for (name, lv) in asked {
        if !level_name_ok(name) {
            return Err(format!("level {name}: not a level's name"));
        }
        let mine = own.get(name).copied().unwrap_or(0);
        if *lv < 0 || *lv > mine {
            return Err(format!("level {name} = {lv}: above your own, {mine}"));
        }
        caps.insert(name.clone(), *lv);
    }
    Ok(caps)
}

/// [levels] The levels a query string asks for: `level=2` (the unnamed one, `sal`) and
/// `level.<name>=3`; other keys are not its
pub fn asked_from_query(query: &str) -> Result<Vec<(String, i16)>, String> {
    let mut out = Vec::new();
    // [review 2026-11-22] a key or a value written percent-encoded is the same ask: decoded first, so
    // none is passed by - and a key that starts as a level's and is none is refused, not dropped
    let decoded = |s: &str| -> String {
        let b = s.as_bytes();
        let (mut out, mut i) = (Vec::with_capacity(b.len()), 0);
        while i < b.len() {
            let hex = |x: u8| (x as char).to_digit(16).map(|d| d as u8);
            match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                (b'%', Some(h), Some(l)) => { out.push(h * 16 + l); i += 3; }
                (b'+', _, _) => { out.push(b' '); i += 1; }
                (c, _, _) => { out.push(c); i += 1; }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    };
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (k, v) = (decoded(k), decoded(v));
        let (k, v) = (k.as_str(), v.as_str());
        let name = match k {
            "level" => SAL,
            k => match k.strip_prefix("level.") {
                Some(n) => n,
                None if k.starts_with("level") => return Err(format!("{k}: level, or level.<name>")),
                None => continue,
            },
        };
        let lv: i16 = v.trim().parse().map_err(|_| format!("level {name}: {v} is not a number"))?;
        if !level_name_ok(name) {
            return Err(format!("level {name}: not a level's name"));
        }
        out.push((name.to_string(), lv));
    }
    Ok(out)
}

/// A label a subject holds
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct Label {
    pub key: String,
    pub value: String,
    pub level: i16,
}

/// What labac knows of an account (`labac_subjects`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Subject {
    pub user_id: Uuid,
    pub groups: BTreeSet<String>,
    pub labels: BTreeSet<Label>,
    pub ceiling: Option<i16>,
    /// bumped by every change
    pub version: i64,
    /// the rules that made it, by id
    #[serde(default)]
    pub rules: Vec<i64>,
    /// [labac] the PostgreSQL group roles its rules gave, in rule order: ytproxy logs in to a
    /// node as the one granted what a transaction's tables need
    #[serde(default)]
    pub pg_roles: Vec<String>,
    /// [levels] the person's named levels (`sal`, ...): its own rows over what its rules gave; a name
    /// it has none of is 0 - no row of a table that declares that level. A body stored before the
    /// levels reads with none.
    #[serde(default)]
    pub levels: BTreeMap<String, i16>,
    /// [levels] what the rules alone gave: `levels` is worked out of it again when a person's row changes
    #[serde(default)]
    pub rule_levels: BTreeMap<String, i16>,
}

impl Subject {
    fn same_access(&self, other: &Subject) -> bool {
        self.groups == other.groups && self.labels == other.labels && self.ceiling == other.ceiling
            && self.pg_roles == other.pg_roles && self.levels == other.levels
    }

    /// the levels of `key` = `value` this subject holds, the highest; `None` none
    fn label_level(&self, key: &str, value: &str) -> Option<i16> {
        self.labels.iter().filter(|l| l.key == key && l.value == value).map(|l| l.level).max()
    }
}

/// `value` matched by `kind` / `pattern` (or the claim's `id`): `$0`, `$1`.. - `None` no match
pub fn captures(kind: MatchKind, pattern: &str, value: &str, id: Option<&str>) -> Option<Vec<String>> {
    match kind {
        MatchKind::Name => (value == pattern).then(|| vec![value.to_string()]),
        MatchKind::Prefix => value.strip_prefix(pattern).map(|rest| vec![value.to_string(), rest.to_string()]),
        MatchKind::Id => (id == Some(pattern)).then(|| vec![value.to_string()]),
        MatchKind::Regex => {
            let re = regex::Regex::new(&format!("^(?:{})$", pattern)).ok()?;
            let c = re.captures(value)?;
            Some(c.iter().map(|m| m.map(|m| m.as_str().to_string()).unwrap_or_default()).collect())
        }
    }
}

/// `template` with `$0`..`$9` replaced by `caps`; one past them, empty
pub fn substitute(template: &str, caps: &[String]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                chars.next();
                out.push_str(caps.get(d as usize).map(String::as_str).unwrap_or(""));
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// [labac] The subject the rules make of `claims`; `before` the one held - kept with its
/// version when nothing of its access changed, else the next version
pub fn map_subject(user_id: Uuid, rules: &[Rule], claims: &[Claim], before: Option<&Subject>) -> Subject {
    map_subject_with(user_id, rules, claims, &BTreeMap::new(), before)
}

/// [levels] [`map_subject`] with the person's own level rows (`labac_levels`), which stand over the
/// levels the rules give. The ceiling is the action scale's: it caps no named level.
pub fn map_subject_with(user_id: Uuid, rules: &[Rule], claims: &[Claim], person: &BTreeMap<String, i16>, before: Option<&Subject>) -> Subject {
    let mut s = Subject { user_id, ..Default::default() };
    for r in rules {
        for c in claims {
            if (r.source != "*" && r.source != c.source) || r.claim != c.name {
                continue;
            }
            let Some(caps) = captures(r.kind, &r.pattern, &c.value, c.id.as_deref()) else { continue };
            if let Some(g) = &r.group {
                let g = substitute(g, &caps);
                if !g.is_empty() {
                    s.groups.insert(g);
                }
            }
            if let (Some(k), Some(v)) = (&r.label_key, &r.label_value) {
                let (k, v) = (substitute(k, &caps), substitute(v, &caps));
                if !k.is_empty() && !v.is_empty() {
                    s.labels.insert(Label { key: k, value: v, level: r.level });
                }
            }
            if let Some(cap) = r.ceiling {
                s.ceiling = Some(s.ceiling.map_or(cap, |c| c.min(cap)));
            }
            if let Some(role) = &r.pg_role {
                let role = substitute(role, &caps);
                if !role.is_empty() && !s.pg_roles.contains(&role) {
                    s.pg_roles.push(role);
                }
            }
            // [levels] a named level: the highest of the rules that match. What is no level - a name
            // that is none, a value that is no number of 0 or more - is said and gives nothing
            if let (Some(n), Some(v)) = (&r.level_name, &r.level_value) {
                let (n, v) = (substitute(n, &caps), substitute(v, &caps));
                match v.trim().parse::<i16>() {
                    Ok(lv) if lv >= 0 && level_name_ok(&n) => {
                        let e = s.rule_levels.entry(n).or_insert(0);
                        *e = (*e).max(lv);
                    }
                    _ => tracing::warn!(rule = r.id, name = %n, value = %v, "labac rule: not a level - it gives none"),
                }
            }
            if !s.rules.contains(&r.id) {
                s.rules.push(r.id);
            }
        }
    }
    s.levels = effective_levels(&s.rule_levels, person);
    s.version = match before {
        Some(b) if b.same_access(&s) => b.version,
        Some(b) => b.version + 1,
        None => 1,
    };
    s
}

/// A resource (`labac_resources`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Resource {
    pub kind: String,
    pub id: String,
    /// its parent: kind and id
    #[serde(default)]
    pub parent: Option<(String, String)>,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// takes only its own entries, none shared down from a parent
    #[serde(default)]
    pub private: bool,
}

/// An ACL entry (`labac_entries`)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Entry {
    pub id: i64,
    pub kind: String,
    pub resource: String,
    /// the ABAC group it is for; `*` any subject
    pub group: String,
    /// [labac] the one person it is for: counted only while that person is
    /// in `group`; `None` an entry of the group
    #[serde(default)]
    pub user_id: Option<Uuid>,
    /// `key` (the resource's label is the subject's) or `key=value` (the subject's label)
    #[serde(default)]
    pub label: Option<String>,
    pub level: i16,
    /// given down to the resource's children too
    #[serde(default)]
    pub shared: bool,
}

/// Why a subject has its level on a resource
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Why {
    pub level: i16,
    /// the entry that gave it, and the resource it is on
    pub entry: Option<i64>,
    pub on: Option<(String, String)>,
    /// the label it matched through
    pub label: Option<String>,
    /// the subject's ceiling cut it down
    pub capped: bool,
}

/// [labac] The actions a level is asked for, lowest first: a soft delete
/// is an UPDATE that sets the table's soft-delete column; `cleanup` is gone - a purge is a delete
pub const ACTIONS: &[&str] = &["select", "insert", "update", "soft_delete", "delete", "ddl"];

/// [approval] The actions of an approval, lowest first: a second scale of the same levels, for
/// what people decide rather than what a statement does - view 1, comment 2, recommend 3,
/// approve 4, veto 5, override 6. A level gives its action and every one below it, so to approve
/// is not yet to veto: a veto blocks an approval and ends the voting, an override lifts a veto.
/// What a caller makes of them is the caller's (an etcd server counts approvals of a queue's
/// messages by them); a kind may set its own levels (`set_action`), as for [`ACTIONS`]
pub const APPROVAL_ACTIONS: &[&str] = &["view", "comment", "recommend", "approve", "veto", "override"];

/// the level an action needs when its kind's map says nothing: its place on its scale -
/// [`ACTIONS`] or [`APPROVAL_ACTIONS`]
pub fn default_action_level(action: &str) -> Option<i16> {
    match action {
        "select" | "view" => Some(1),
        "insert" | "comment" => Some(2),
        "update" | "recommend" => Some(3),
        "soft_delete" | "approve" => Some(4),
        "delete" | "veto" => Some(5),
        "ddl" | "override" => Some(6),
        _ => None,
    }
}

/// A SQL fragment and its parameters: `{column} = ANY($n)` with the ids, `TRUE`, or `FALSE`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predicate {
    pub sql: String,
    pub params: Vec<Vec<String>>,
}

/// [labac] The resources, entries and actions, as loaded: what a level is decided on
#[derive(Debug, Clone, Default)]
pub struct Acl {
    pub resources: HashMap<(String, String), Resource>,
    pub entries: HashMap<(String, String), Vec<Entry>>,
    pub actions: HashMap<(String, String), i16>,
}

/// how many parents up a level looks at most: a loop in the data ends there
const MAX_DEPTH: usize = 64;

/// [levels] the resource id of an entry that is for every resource of its kind. No resource has it.
pub const ANY: &str = "*";

impl Acl {
    pub fn add_resource(&mut self, r: Resource) {
        self.resources.insert((r.kind.clone(), r.id.clone()), r);
    }

    pub fn add_entry(&mut self, e: Entry) {
        self.entries.entry((e.kind.clone(), e.resource.clone())).or_default().push(e);
    }

    /// an entry's level for `s` on resource `r` - [review 2026-11-21] the resource asked about,
    /// also for an entry shared down from a parent - and the label it matched through
    fn entry_level(e: &Entry, s: &Subject, r: Option<&Resource>) -> Option<(i16, Option<String>)> {
        if e.group != "*" && !s.groups.contains(&e.group) {
            return None;
        }
        // [labac] a person's own entry: that person only, and only while in the group (above)
        if e.user_id.is_some_and(|u| u != s.user_id) {
            return None;
        }
        let Some(cond) = &e.label else {
            return Some((e.level, None));
        };
        let (key, value) = match cond.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => (cond.trim().to_string(), r?.labels.get(cond.trim())?.clone()),
        };
        let l = s.label_level(&key, &value)?;
        let level = if l > 0 { e.level.min(l) } else { e.level };
        Some((level, Some(format!("{}={}", key, value))))
    }

    /// [levels] `s`'s level on every resource of `kind`: from the entries on resource `*` alone, the
    /// ceiling over it. An entry whose label condition reads the resource's label (`key`, no value)
    /// is of one resource at a time: it gives nothing here.
    pub fn any_level(&self, s: &Subject, kind: &str) -> i16 {
        let lv = self.entries.get(&(kind.to_string(), ANY.to_string())).map(Vec::as_slice).unwrap_or(&[]).iter()
            .filter_map(|e| Self::entry_level(e, s, None)).map(|(lv, _)| lv).max().unwrap_or(0);
        match s.ceiling {
            Some(c) => lv.min(c.max(0)),
            None => lv,
        }
    }

    /// [levels] whether `s` may `action` every resource of `kind`, whatever its id - one that has no
    /// row in `labac_resources` too: an entry on `*` gives it. The condition on the kind is then left
    /// out of a statement; the levels a table declares still hold.
    pub fn any(&self, s: &Subject, kind: &str, action: &str) -> bool {
        let Some(need) = self.action_level(kind, action) else { return false };
        let got = self.any_level(s, kind);
        got > 0 && got >= need
    }

    /// [labac] `s`'s level on resource `kind`/`id`, and why
    pub fn level(&self, s: &Subject, kind: &str, id: &str) -> Why {
        let mut best = Why::default();
        let target = self.resources.get(&(kind.to_string(), id.to_string()));
        // [levels] an entry on `*` is every resource's own - a private one's too: it is not shared
        // down from a parent
        let every = (kind.to_string(), ANY.to_string());
        for e in self.entries.get(&every).map(Vec::as_slice).unwrap_or(&[]) {
            if let Some((lv, label)) = Self::entry_level(e, s, target) {
                if lv > best.level {
                    best = Why { level: lv, entry: Some(e.id), on: Some(every.clone()), label, capped: false };
                }
            }
        }
        let mut at = Some((kind.to_string(), id.to_string()));
        let mut own = true;
        for _ in 0..MAX_DEPTH {
            let Some(k) = at else { break };
            let r = self.resources.get(&k);
            for e in self.entries.get(&k).map(Vec::as_slice).unwrap_or(&[]) {
                if !own && !e.shared {
                    continue;
                }
                if let Some((lv, label)) = Self::entry_level(e, s, target) {
                    if lv > best.level {
                        best = Why { level: lv, entry: Some(e.id), on: Some(k.clone()), label, capped: false };
                    }
                }
            }
            if own && r.is_some_and(|r| r.private) {
                break;
            }
            at = r.and_then(|r| r.parent.clone());
            own = false;
        }
        if let Some(c) = s.ceiling {
            if best.level > c {
                best.level = c.max(0);
                best.capped = true;
            }
        }
        best
    }

    /// the level `action` needs on a resource of `kind`: the kind's map, else the defaults
    pub fn action_level(&self, kind: &str, action: &str) -> Option<i16> {
        self.actions.get(&(kind.to_string(), action.to_string())).copied().or_else(|| default_action_level(action))
    }

    /// [labac] whether `s` may `action` resource `kind`/`id`; an action with no level, no. signon's own
    /// levels only - [review 2026-11-21] where an OPA is set, [`Opa::allowed`] is the answer
    pub fn allowed(&self, s: &Subject, kind: &str, id: &str, action: &str) -> bool {
        let Some(need) = self.action_level(kind, action) else { return false };
        let got = self.level(s, kind, id).level;
        got > 0 && got >= need
    }

    /// [labac] the ids of `kind` `s` may `action`, in order - of the resources `labac_resources` holds:
    /// [review 2026-11-21] an entry on an id with no resource row reaches nothing
    pub fn reach(&self, s: &Subject, kind: &str, action: &str) -> Vec<String> {
        let mut ids: Vec<String> = self.resources.keys().filter(|(k, _)| k == kind)
            .filter(|(k, id)| self.allowed(s, k, id, action)).map(|(_, id)| id.clone()).collect();
        ids.sort();
        ids
    }

    /// [labac] A SQL fragment for ytproxy: rows of `kind` whose `column` - an identifier the
    /// caller quotes - is an id `s` may `action`; `param` the placeholder's number
    pub fn predicate(&self, s: &Subject, kind: &str, action: &str, column: &str, param: usize) -> Predicate {
        let ids = self.reach(s, kind, action);
        if ids.is_empty() {
            return Predicate { sql: "FALSE".into(), params: vec![] };
        }
        Predicate { sql: format!("{} = ANY(${})", column, param), params: vec![ids] }
    }
}

/// [labac] The person's token and OPA, all off unless set: see
/// [`crate::Config::with_labac`]
#[derive(Clone, Default)]
pub struct LabacConfig {
    /// the HS256 key a person's token ([`issue`]) is signed with - ytproxy checks it with the
    /// same key; `None`: no `/labac/token` page
    pub token_key: Option<Vec<u8>>,
    /// how long such a token lasts (8 hours unless set)
    pub token_ttl: Option<std::time::Duration>,
    /// [opa] where an OPA server gives the levels
    #[cfg(feature = "opa")]
    pub opa: Option<Arc<Opa>>,
}

impl std::fmt::Debug for LabacConfig {
    /// the key is a secret: only whether there is one
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabacConfig").field("token_key", &self.token_key.as_ref().map(|_| "<redacted>"))
            .field("token_ttl", &self.token_ttl).finish()
    }
}

/// [levels] A person's own named levels as the configuration has them: the subject's - its rows
/// over its rules - and, for the names an OPA is set for, the OPA's answer in their place. An OPA
/// that does not answer is an error: no level is given on a guess.
pub async fn own_levels(config: &LabacConfig, s: &Subject) -> anyhow::Result<BTreeMap<String, i16>> {
    #[allow(unused_mut)]
    let mut own = s.levels.clone();
    #[cfg(feature = "opa")]
    if let Some(o) = config.opa.as_ref().filter(|o| !o.level_names().is_empty()) {
        let given = o.named_levels(s).await?;
        for n in o.level_names() {
            own.insert(n.clone(), given.get(n).copied().unwrap_or(0));
        }
    }
    #[cfg(not(feature = "opa"))]
    let _ = config;
    Ok(own)
}

/// how long a person's token lasts unless the configuration says
pub const TOKEN_TTL: std::time::Duration = std::time::Duration::from_secs(8 * 3600);

/// [opa] An OPA server's levels (feature `opa`): for the kinds it is set for
/// (all, when none are named) it is asked once per subject version and kind - `POST url` with
/// `{"input": {"subject", "kind", "resources"}}` - and answers `{"result": {"<id>": level}}`.
/// A level it gives is the resource's (raising or lowering signon's own), the subject's ceiling
/// still caps it; a resource it does not name keeps signon's level; an answer it does not give
/// (an error, a timeout, no result, not a map) is an error - the caller grants nothing of that kind then.
#[cfg(feature = "opa")]
pub struct Opa {
    url: String,
    kinds: Vec<String>,
    cache_for: std::time::Duration,
    client: reqwest::Client,
    cache: std::sync::Mutex<HashMap<(Uuid, i64, String, u64), (std::time::Instant, Arc<HashMap<String, i16>>)>>,
    /// [levels] where it gives a person's named levels, and which names ([`Opa::with_named_levels`])
    levels_url: Option<String>,
    level_names: Vec<String>,
    named: std::sync::Mutex<HashMap<(Uuid, i64), (std::time::Instant, Arc<BTreeMap<String, i16>>)>>,
}

/// the answers an [`Opa`] keeps at most: past it the cache starts again
#[cfg(feature = "opa")]
const OPA_CACHE_MAX: usize = 10_000;

#[cfg(feature = "opa")]
impl Opa {
    /// `url` the policy's data API (`http://opa:8181/v1/data/labac/levels`); `kinds` the
    /// kinds it gives levels for, empty all; an answer kept `cache_for` at most (the policy's
    /// data changes without the subject's version)
    pub fn new(url: impl Into<String>, kinds: Vec<String>, cache_for: std::time::Duration) -> anyhow::Result<Opa> {
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build()?;
        Ok(Opa { url: url.into(), kinds, cache_for, client, cache: std::sync::Mutex::new(HashMap::new()),
            levels_url: None, level_names: Vec::new(), named: std::sync::Mutex::new(HashMap::new()) })
    }

    /// [levels] also a person's named levels: for `names` (`sal`, ...) the policy at `url` is asked -
    /// `POST url` with `{"input": {"subject", "levels": [names]}}` - and answers
    /// `{"result": {"<name>": level}}`. Its answer is the person's level of those names, in place of
    /// signon's own (a name it leaves out: 0); no answer is an error - the caller gives no level then.
    pub fn with_named_levels(mut self, url: impl Into<String>, names: Vec<String>) -> Opa {
        self.levels_url = Some(url.into());
        self.level_names = names;
        self
    }

    /// [levels] the names it gives a person's level of
    pub fn level_names(&self) -> &[String] {
        if self.levels_url.is_some() { &self.level_names } else { &[] }
    }

    /// [levels] `s`'s levels of [`Opa::level_names`], asked once per subject version and kept `cache_for`
    pub async fn named_levels(&self, s: &Subject) -> anyhow::Result<Arc<BTreeMap<String, i16>>> {
        let Some(url) = self.levels_url.as_ref().filter(|_| !self.level_names.is_empty()) else {
            return Ok(Arc::new(BTreeMap::new()));
        };
        let key = (s.user_id, s.version);
        if let Some((at, m)) = self.named.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
            if at.elapsed() < self.cache_for {
                return Ok(m.clone());
            }
        }
        let input = serde_json::json!({ "input": {
            "subject": { "user_id": s.user_id, "groups": s.groups, "labels": s.labels, "ceiling": s.ceiling, "version": s.version,
                "levels": s.levels },
            "levels": self.level_names,
        }});
        let answer: serde_json::Value = self.client.post(url).json(&input).send().await?.error_for_status()?.json().await?;
        let mut m = BTreeMap::new();
        match answer.get("result") {
            None | Some(serde_json::Value::Null) => anyhow::bail!("opa: no result: the policy gives no named levels at this path"),
            Some(serde_json::Value::Object(o)) => {
                for n in &self.level_names {
                    let lv = match o.get(n) {
                        None | Some(serde_json::Value::Null) => 0,
                        Some(v) => v.as_i64().ok_or_else(|| anyhow::anyhow!("opa: the level {n} is no number"))?,
                    };
                    m.insert(n.clone(), lv.clamp(0, i16::MAX as i64) as i16);
                }
            }
            Some(_) => anyhow::bail!("opa: the result is not a map of named levels"),
        }
        let m = Arc::new(m);
        let mut cache = self.named.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= OPA_CACHE_MAX {
            cache.clear();
        }
        cache.insert(key, (std::time::Instant::now(), m.clone()));
        Ok(m)
    }

    /// whether it gives the levels of `kind`
    pub fn covers(&self, kind: &str) -> bool {
        self.kinds.is_empty() || self.kinds.iter().any(|k| k == kind)
    }

    /// the levels it gives `s` on the resources of `kind`
    pub async fn levels(&self, acl: &Acl, s: &Subject, kind: &str) -> anyhow::Result<Arc<HashMap<String, i16>>> {
        let mut resources: Vec<&Resource> = acl.resources.values().filter(|r| r.kind == kind).collect();
        resources.sort_by(|a, b| a.id.cmp(&b.id));
        // [review 2026-11-21] the answer is kept for the resources as they are: one added, moved or
        // relabelled asks again
        let state = {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            for r in &resources {
                (&r.id, &r.parent, &r.private).hash(&mut h);
                let mut labels: Vec<(&String, &String)> = r.labels.iter().collect();
                labels.sort();
                labels.hash(&mut h);
            }
            h.finish()
        };
        let key = (s.user_id, s.version, kind.to_string(), state);
        if let Some((at, m)) = self.cache.lock().unwrap_or_else(|p| p.into_inner()).get(&key) {
            if at.elapsed() < self.cache_for {
                return Ok(m.clone());
            }
        }
        let input = serde_json::json!({ "input": {
            "subject": { "user_id": s.user_id, "groups": s.groups, "labels": s.labels, "ceiling": s.ceiling, "version": s.version },
            "kind": kind,
            "resources": resources.iter().map(|r| serde_json::json!({ "id": r.id, "labels": r.labels,
                "parent": r.parent.as_ref().map(|(k, i)| serde_json::json!({ "kind": k, "id": i })) })).collect::<Vec<_>>(),
        }});
        let answer: serde_json::Value = self.client.post(&self.url).json(&input).send().await?.error_for_status()?.json().await?;
        let mut m = HashMap::new();
        match answer.get("result") {
            // [review 2026-11-21] no result (an undefined rule or path): no answer, as the docs say
            None | Some(serde_json::Value::Null) => anyhow::bail!("opa: no result: the policy gives no levels at this path"),
            Some(serde_json::Value::Object(o)) => {
                for (id, v) in o {
                    let lv = v.as_i64().ok_or_else(|| anyhow::anyhow!("opa: the level of {id} is no number"))?;
                    m.insert(id.clone(), lv.clamp(0, i16::MAX as i64) as i16);
                }
            }
            Some(_) => anyhow::bail!("opa: the result is not a map of levels"),
        }
        let m = Arc::new(m);
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        if cache.len() >= OPA_CACHE_MAX {
            cache.clear();
        }
        cache.insert(key, (std::time::Instant::now(), m.clone()));
        Ok(m)
    }
}

#[cfg(feature = "opa")]
impl Opa {
    /// [opa] [review 2026-11-21] [`Acl::allowed`] with this OPA's levels for a kind it is set for: an OPA
    /// that does not answer is an error - not allowed
    pub async fn allowed(&self, acl: &Acl, s: &Subject, kind: &str, id: &str, action: &str) -> anyhow::Result<bool> {
        if !self.covers(kind) {
            return Ok(acl.allowed(s, kind, id, action));
        }
        let Some(need) = acl.action_level(kind, action) else { return Ok(false) };
        let given = self.levels(acl, s, kind).await?;
        let mut lv = given.get(id).copied().unwrap_or_else(|| acl.level(s, kind, id).level);
        if let Some(c) = s.ceiling {
            lv = lv.min(c.max(0));
        }
        Ok(lv > 0 && lv >= need)
    }

    /// [opa] [`Acl::reach`] with this OPA's levels for a kind it is set for, else signon's own: an
    /// OPA that does not answer is an error - nothing of the kind. A method, not a parameter of a
    /// function: a crate that never names OPA builds the same whatever features signon has
    pub async fn reach(&self, acl: &Acl, s: &Subject, kind: &str, action: &str) -> anyhow::Result<Vec<String>> {
        if !self.covers(kind) {
            return Ok(acl.reach(s, kind, action));
        }
        let Some(need) = acl.action_level(kind, action) else { return Ok(Vec::new()) };
        let given = self.levels(acl, s, kind).await?;
        let mut ids: Vec<String> = acl.resources.keys().filter(|(k, _)| k == kind).filter_map(|(_, id)| {
            let mut lv = given.get(id).copied().unwrap_or_else(|| acl.level(s, kind, id).level);
            if let Some(c) = s.ceiling {
                lv = lv.min(c.max(0));
            }
            (lv > 0 && lv >= need).then(|| id.clone())
        }).collect();
        ids.sort();
        Ok(ids)
    }
}

/// [labac] What the embedder is told when a subject's version moves: YT Cluster writes an
/// etcd key ytproxy and yui watch, so a token of the version before is caught at once
pub trait SubjectHook: Send + Sync {
    fn changed(&self, user_id: Uuid, version: i64);
}

static HOOK: RwLock<Option<Arc<dyn SubjectHook>>> = RwLock::new(None);

/// [labac] The embedder's hook for a subject's new version
pub fn set_hook(hook: Arc<dyn SubjectHook>) {
    *HOOK.write().unwrap_or_else(|p| p.into_inner()) = Some(hook);
}

fn tell(user_id: Uuid, version: i64) {
    if let Some(h) = HOOK.read().unwrap_or_else(|p| p.into_inner()).as_ref() {
        h.changed(user_id, version);
    }
}

// ---- the tables -------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: i64,
    source: String,
    claim: String,
    match_kind: String,
    pattern: String,
    abac_group: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
    level: i16,
    ceiling: Option<i16>,
    pg_role: Option<String>,
    level_name: Option<String>,
    level_value: Option<String>,
}

/// [labac] The mapping rules, in id order. [review 2026-11-21] A rule that does not read - an
/// unknown match kind, a regex that does not compile - fails it: a rule left out could be the
/// one that caps a subject
pub async fn rules(pool: &PgPool) -> anyhow::Result<Vec<Rule>> {
    let rows: Vec<RuleRow> = sqlx::query_as("SELECT id, source, claim, match_kind, pattern, abac_group, label_key, \
        label_value, level, ceiling, pg_role, level_name, level_value FROM labac_rules ORDER BY id").fetch_all(pool).await?;
    rows.into_iter().map(|r| {
        let kind = MatchKind::parse(&r.match_kind)
            .ok_or_else(|| anyhow::anyhow!("labac rule {}: no match kind {}", r.id, r.match_kind))?;
        if kind == MatchKind::Regex {
            regex::Regex::new(&r.pattern).map_err(|e| anyhow::anyhow!("labac rule {}: {e}", r.id))?;
        }
        Ok(Rule { id: r.id, source: r.source, claim: r.claim, kind, pattern: r.pattern, group: r.abac_group,
            label_key: r.label_key, label_value: r.label_value, level: r.level, ceiling: r.ceiling, pg_role: r.pg_role,
            level_name: r.level_name, level_value: r.level_value })
    }).collect()
}

/// [labac] A rule added; its id
pub async fn add_rule(pool: &PgPool, r: &Rule) -> anyhow::Result<i64> {
    if r.kind == MatchKind::Regex {
        regex::Regex::new(&r.pattern).map_err(|e| anyhow::anyhow!("rule pattern: {e}"))?;
    }
    // [levels] a level's name and value go together; a name with no `$` in it is one, a value with
    // none a number of 0 or more - what a claim's capture gives is checked when it is mapped
    match (&r.level_name, &r.level_value) {
        (None, None) => {}
        (Some(n), Some(v)) => {
            if !n.contains('$') && !level_name_ok(n) {
                anyhow::bail!("rule level name {n}: letters, digits and _");
            }
            if !v.contains('$') && !v.trim().parse::<i16>().is_ok_and(|l| l >= 0) {
                anyhow::bail!("rule level value {v}: a number of 0 or more, or a capture ($1)");
            }
        }
        _ => anyhow::bail!("rule level: a name and a value, both"),
    }
    let (id,): (i64,) = sqlx::query_as("INSERT INTO labac_rules (source, claim, match_kind, pattern, abac_group, \
        label_key, label_value, level, ceiling, pg_role, level_name, level_value) \
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING id")
        .bind(&r.source).bind(&r.claim).bind(r.kind.as_str()).bind(&r.pattern).bind(&r.group)
        .bind(&r.label_key).bind(&r.label_value).bind(r.level).bind(r.ceiling).bind(&r.pg_role)
        .bind(&r.level_name).bind(&r.level_value)
        .fetch_one(pool).await?;
    Ok(id)
}

/// [labac] An account's subject, as last made
pub async fn subject(pool: &PgPool, user_id: Uuid) -> anyhow::Result<Option<Subject>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT body FROM labac_subjects WHERE user_id = $1")
        .bind(user_id).fetch_optional(pool).await?;
    Ok(row.and_then(|(b,)| serde_json::from_str(&b).ok()))
}

/// [labac] The subject the rules make of what the IdP said at a sign-in or a SCIM change -
/// stored, and its new version told to the hook, when its access changed. [review 2026-11-21]
/// One remap of an account at a time (a transaction holding its lock): two at once - a
/// sign-in and a SCIM change - each read the version the other wrote, so neither is lost and
/// no two states share a version; a stored body that does not read goes on from its version.
pub async fn remap(pool: &PgPool, user_id: Uuid, claims: &[Claim]) -> anyhow::Result<Subject> {
    let rules = rules(pool).await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('labac:' || $1::text, 0))")
        .bind(user_id).execute(&mut *tx).await?;
    let row: Option<(i64, String)> = sqlx::query_as("SELECT version, body FROM labac_subjects WHERE user_id = $1")
        .bind(user_id).fetch_optional(&mut *tx).await?;
    let before = row.map(|(v, b)| serde_json::from_str::<Subject>(&b).ok().map(|s| Subject { version: v, ..s })
        .unwrap_or(Subject { user_id, version: v, ceiling: Some(-1), ..Default::default() }));
    // [levels] the person's own level rows, read under the same lock: they stand over the rules'
    let person: BTreeMap<String, i16> = sqlx::query_as::<_, (String, i16)>("SELECT name, level FROM labac_levels WHERE user_id = $1")
        .bind(user_id).fetch_all(&mut *tx).await?.into_iter().collect();
    let s = map_subject_with(user_id, &rules, claims, &person, before.as_ref());
    let moved = before.as_ref().map(|b| b.version) != Some(s.version);
    if before.as_ref() != Some(&s) {
        sqlx::query("INSERT INTO labac_subjects (user_id, version, body, updated_at) VALUES ($1, $2, $3, now()) \
            ON CONFLICT (user_id) DO UPDATE SET version = EXCLUDED.version, body = EXCLUDED.body, updated_at = now()")
            .bind(user_id).bind(s.version).bind(serde_json::to_string(&s)?).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    if moved {
        tell(user_id, s.version);
    }
    Ok(s)
}

#[derive(sqlx::FromRow)]
struct ResourceRow {
    kind: String,
    id: String,
    parent_kind: Option<String>,
    parent_id: Option<String>,
    labels: String,
    private: bool,
}

#[derive(sqlx::FromRow)]
struct EntryRow {
    id: i64,
    kind: String,
    resource_id: String,
    abac_group: String,
    user_id: Option<Uuid>,
    label_cond: Option<String>,
    level: i16,
    shared: bool,
}

/// [labac] Every resource, entry and action: what [`Acl`] decides on
pub async fn load_acl(pool: &PgPool) -> anyhow::Result<Acl> {
    let mut acl = Acl::default();
    let rows: Vec<ResourceRow> = sqlx::query_as("SELECT kind, id, parent_kind, parent_id, labels, private FROM labac_resources")
        .fetch_all(pool).await?;
    for r in rows {
        acl.add_resource(Resource { kind: r.kind, id: r.id, parent: r.parent_kind.zip(r.parent_id),
            labels: serde_json::from_str(&r.labels).unwrap_or_default(), private: r.private });
    }
    let rows: Vec<EntryRow> = sqlx::query_as("SELECT id, kind, resource_id, abac_group, user_id, label_cond, level, shared FROM labac_entries")
        .fetch_all(pool).await?;
    for e in rows {
        acl.add_entry(Entry { id: e.id, kind: e.kind, resource: e.resource_id, group: e.abac_group, user_id: e.user_id,
            label: e.label_cond, level: e.level, shared: e.shared });
    }
    let rows: Vec<(String, String, i16)> = sqlx::query_as("SELECT kind, action, level FROM labac_actions").fetch_all(pool).await?;
    for (k, a, l) in rows {
        acl.actions.insert((k, a), l);
    }
    Ok(acl)
}

/// [labac] A resource put, as it is now
pub async fn put_resource(pool: &PgPool, r: &Resource) -> anyhow::Result<()> {
    // [levels] `*` is no resource: an entry on it is for every resource of the kind
    if r.id == ANY || r.parent.as_ref().is_some_and(|p| p.1 == ANY) {
        anyhow::bail!("resource id {ANY}: reserved - an entry on it is for every resource of the kind");
    }
    sqlx::query("INSERT INTO labac_resources (kind, id, parent_kind, parent_id, labels, private) VALUES ($1, $2, $3, $4, $5, $6) \
        ON CONFLICT (kind, id) DO UPDATE SET parent_kind = EXCLUDED.parent_kind, parent_id = EXCLUDED.parent_id, \
        labels = EXCLUDED.labels, private = EXCLUDED.private")
        .bind(&r.kind).bind(&r.id).bind(r.parent.as_ref().map(|p| &p.0)).bind(r.parent.as_ref().map(|p| &p.1))
        .bind(serde_json::to_string(&r.labels)?).bind(r.private).execute(pool).await?;
    Ok(())
}

/// [labac] An entry added; its id
pub async fn add_entry(pool: &PgPool, e: &Entry) -> anyhow::Result<i64> {
    let (id,): (i64,) = sqlx::query_as("INSERT INTO labac_entries (kind, resource_id, abac_group, user_id, label_cond, level, shared) \
        VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id")
        .bind(&e.kind).bind(&e.resource).bind(&e.group).bind(e.user_id).bind(&e.label).bind(e.level).bind(e.shared)
        .fetch_one(pool).await?;
    Ok(id)
}

/// [levels] A person's own level rows (`labac_levels`), by name
pub async fn person_levels(pool: &PgPool, user_id: Uuid) -> anyhow::Result<BTreeMap<String, i16>> {
    Ok(sqlx::query_as::<_, (String, i16)>("SELECT name, level FROM labac_levels WHERE user_id = $1")
        .bind(user_id).fetch_all(pool).await?.into_iter().collect())
}

/// [levels] A person's own level of `name` set - it stands over what the rules give - or, with
/// `None`, taken away (the rules' level counts again). One change of an account at a time, as a
/// remap; the stored subject takes it at once: its version moves and the hook is told, so a session
/// held on the level before does not keep it. A person with no subject yet gets it at its first sign-in.
pub async fn set_level(pool: &PgPool, user_id: Uuid, name: &str, level: Option<i16>) -> anyhow::Result<()> {
    if !level_name_ok(name) {
        anyhow::bail!("level name {name}: letters, digits and _");
    }
    if level.is_some_and(|l| l < 0) {
        anyhow::bail!("level {name}: 0 or more");
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('labac:' || $1::text, 0))")
        .bind(user_id).execute(&mut *tx).await?;
    match level {
        Some(l) => sqlx::query("INSERT INTO labac_levels (user_id, name, level) VALUES ($1, $2, $3) \
            ON CONFLICT (user_id, name) DO UPDATE SET level = EXCLUDED.level").bind(user_id).bind(name).bind(l).execute(&mut *tx).await?,
        None => sqlx::query("DELETE FROM labac_levels WHERE user_id = $1 AND name = $2").bind(user_id).bind(name).execute(&mut *tx).await?,
    };
    let row: Option<(i64, String)> = sqlx::query_as("SELECT version, body FROM labac_subjects WHERE user_id = $1")
        .bind(user_id).fetch_optional(&mut *tx).await?;
    let mut told = None;
    if let Some((version, body)) = row {
        // [review 2026-11-22] a stored subject that does not read cannot take the level: said, and
        // nothing is written - a lowering is not reported as done when it is not
        let read = serde_json::from_str::<Subject>(&body)
            .map_err(|e| anyhow::anyhow!("labac subject of {user_id} does not read ({e}): sign the account in again, then set its level"));
        {
            let mut s = read?;
            let person: BTreeMap<String, i16> = sqlx::query_as::<_, (String, i16)>("SELECT name, level FROM labac_levels WHERE user_id = $1")
                .bind(user_id).fetch_all(&mut *tx).await?.into_iter().collect();
            let levels = effective_levels(&s.rule_levels, &person);
            if levels != s.levels {
                s.levels = levels;
                s.version = version + 1;
                sqlx::query("UPDATE labac_subjects SET version = $2, body = $3, updated_at = now() WHERE user_id = $1")
                    .bind(user_id).bind(s.version).bind(serde_json::to_string(&s)?).execute(&mut *tx).await?;
                told = Some(s.version);
            }
        }
    }
    tx.commit().await?;
    if let Some(v) = told {
        tell(user_id, v);
    }
    Ok(())
}

/// [labac] The level `action` needs on a resource of `kind`
pub async fn set_action(pool: &PgPool, kind: &str, action: &str, level: i16) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO labac_actions (kind, action, level) VALUES ($1, $2, $3) \
        ON CONFLICT (kind, action) DO UPDATE SET level = EXCLUDED.level")
        .bind(kind).bind(action).bind(level).execute(pool).await?;
    Ok(())
}

// ---- the token ----------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TokenClaims {
    sub: String,
    ver: i64,
    exp: i64,
    iat: i64,
    /// [levels] the levels the token was minted for; left out: no top
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    lv: BTreeMap<String, i16>,
}

/// [review 2026-11-21] the longest a token lasts, whatever is asked: 30 days
pub const MAX_TTL: i64 = 30 * 86_400;

/// [labac] A JWT for `s`: its account and version, valid `ttl_secs`, HS256 under `key`
pub fn issue(key: &[u8], s: &Subject, ttl_secs: i64) -> anyhow::Result<String> {
    issue_at(key, s, ttl_secs, &BTreeMap::new())
}

/// [levels] [`issue`] for the levels asked (`lv`): the token's tops - a session entered with it
/// works at them and no higher, whatever the person's own. None asked: no top, the person's own.
pub fn issue_at(key: &[u8], s: &Subject, ttl_secs: i64, levels: &BTreeMap<String, i16>) -> anyhow::Result<String> {
    crate::jwt_backend();
    // [review 2026-11-21] an empty key signs nothing: anyone could sign with it too
    if key.is_empty() {
        anyhow::bail!("labac token key: empty");
    }
    let now = chrono::Utc::now().timestamp();
    let c = TokenClaims { sub: s.user_id.to_string(), ver: s.version, iat: now, exp: now + ttl_secs.clamp(1, MAX_TTL), lv: levels.clone() };
    let key = jsonwebtoken::EncodingKey::from_secret(key).map_err(|e| anyhow::anyhow!("labac token key: {e}"))?;
    jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256), &c, &key)
        .map_err(|e| anyhow::anyhow!("labac token: {e}"))
}

/// [labac] A token's account and version, signature and expiry checked
pub fn verify(key: &[u8], token: &str) -> anyhow::Result<(Uuid, i64)> {
    verify_levels(key, token).map(|(u, v, _)| (u, v))
}

/// [levels] [`verify`], and the levels the token was minted for: its tops. A token with none - one
/// issued before the levels too - has no top.
pub fn verify_levels(key: &[u8], token: &str) -> anyhow::Result<(Uuid, i64, BTreeMap<String, i16>)> {
    crate::jwt_backend();
    if key.is_empty() {
        anyhow::bail!("labac token key: empty");
    }
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    v.required_spec_claims = ["exp", "sub"].iter().map(|s| s.to_string()).collect();
    // [review 2026-11-21] a few seconds of clock skew, not jsonwebtoken's minute
    v.leeway = 5;
    let key = jsonwebtoken::DecodingKey::from_secret(key).map_err(|e| anyhow::anyhow!("labac token key: {e}"))?;
    let d = jsonwebtoken::decode::<TokenClaims>(token, &key, &v)
        .map_err(|e| anyhow::anyhow!("labac token: {e}"))?;
    Ok((Uuid::parse_str(&d.claims.sub)?, d.claims.ver, d.claims.lv))
}

/// [labac] The subject a token is for, when it is the current version: `None` for a stale
/// token (the subject changed since) or an account with no subject
pub async fn current(pool: &PgPool, key: &[u8], token: &str) -> anyhow::Result<Option<Subject>> {
    let (user, ver) = verify(key, token)?;
    Ok(subject(pool, user).await?.filter(|s| s.version == ver))
}

// ---- the SQL half (optional) ------------------------------------------------------

/// [labac] The SQL half - schema_guard's since 2.5.0 (schema_guard installs it before
/// the policies of a table's `security` declaration), applied here only when the configuration asks ([`apply_sql`]):
/// `labac.enter(token)` - SECURITY DEFINER - checks the HMAC ytproxy signed a token with
/// (pgcrypto) and holds what it says for the transaction; `labac.ids(kind, action)` is what an
/// RLS policy compares a column with. The policies come from schema_guard (a table's `security`
/// declaration, deployed under its rls mode); under lsr, ytproxy rewrites the statement instead.
pub const SQL: &str = schema_guard_tokio::security::SQL;

/// [labac] The SQL half applied to a database, with the key ytproxy signs with: only where
/// the configuration asks for it. Needs a role that may create the extension and the schema.
pub async fn apply_sql(pool: &PgPool, key: &[u8]) -> anyhow::Result<()> {
    sqlx::raw_sql(SQL).execute(pool).await?;
    sqlx::query("INSERT INTO labac.key (id, secret) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret")
        .bind(key).execute(pool).await?;
    Ok(())
}

/// HMAC-SHA256 (RFC 2104), as pgcrypto's `hmac(.., 'sha256')`
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

/// [labac] What ytproxy hands `labac.enter`: the subject's account, the ids it may reach by
/// `kind:action`, valid `ttl_secs` - signed with the key [`apply_sql`] set
pub fn enter_token(key: &[u8], user_id: Uuid, ids: &BTreeMap<String, Vec<String>>, ttl_secs: i64) -> String {
    enter_token_body(key, serde_json::json!({ "sub": user_id.to_string(),
        "exp": chrono::Utc::now().timestamp() + ttl_secs.clamp(1, MAX_TTL), "ids": ids }))
}

/// [labac] [review 2026-11-21] [`enter_token`] for the login `role` only: labac.checked takes it in
/// a session of that role alone (`session_user`), so a copy is no subject anywhere else
pub fn enter_token_for(key: &[u8], user_id: Uuid, role: &str, ids: &BTreeMap<String, Vec<String>>, ttl_secs: i64) -> String {
    enter_token_body(key, serde_json::json!({ "sub": user_id.to_string(),
        "exp": chrono::Utc::now().timestamp() + ttl_secs.clamp(1, MAX_TTL), "ids": ids, "role": role }))
}

/// [levels] [`enter_token_for`] with the kind:action pairs the subject may use whatever the id
/// (`any`: an entry on `*` - never an id in a list) and its named levels at this moment (its own,
/// under the token's tops and what the session asked); `role` `None` for any login
pub fn enter_token_with(key: &[u8], user_id: Uuid, role: Option<&str>, ids: &BTreeMap<String, Vec<String>>, any: &[String],
    levels: &BTreeMap<String, i16>, ttl_secs: i64) -> String {
    let mut body = serde_json::json!({ "sub": user_id.to_string(),
        "exp": chrono::Utc::now().timestamp() + ttl_secs.clamp(1, MAX_TTL), "ids": ids, "any": any, "levels": levels });
    if let Some(r) = role {
        body["role"] = serde_json::Value::String(r.to_string());
    }
    enter_token_body(key, body)
}

fn enter_token_body(key: &[u8], body: serde_json::Value) -> String {
    use base64::Engine;
    let payload = base64::engine::general_purpose::STANDARD.encode(body.to_string());
    let sig: String = hmac_sha256(key, payload.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}.{}", payload, sig)
}

#[cfg(test)]
#[path = "labac_test.rs"]
mod tests;
