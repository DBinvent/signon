//! [labac] the subject the rules make, the levels the ACL gives, the token
use super::*;

fn rule(id: i64, claim: &str, kind: MatchKind, pattern: &str) -> Rule {
    Rule { id, source: "*".into(), claim: claim.into(), kind, pattern: pattern.into(), group: None, label_key: None,
        label_value: None, level: 0, ceiling: None, pg_role: None, level_name: None, level_value: None }
}

/// [labac] the tests that change labac_rules, one at a time: one's DELETE and rules reach another's remap
static RULES_TABLE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn uid() -> Uuid {
    Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()
}

#[test]
fn rules_match_by_name_prefix_regex_and_id_and_fill_their_captures() {
    assert_eq!(captures(MatchKind::Name, "admins", "admins", None), Some(vec!["admins".into()]));
    assert_eq!(captures(MatchKind::Name, "admins", "admins2", None), None);
    assert_eq!(captures(MatchKind::Prefix, "dept-", "dept-sales", None), Some(vec!["dept-sales".into(), "sales".into()]));
    assert_eq!(captures(MatchKind::Regex, r"team-(\w+)-(\d)", "team-ops-3", None),
        Some(vec!["team-ops-3".into(), "ops".into(), "3".into()]));
    assert_eq!(captures(MatchKind::Regex, r"team-(\w+)", "xteam-ops", None), None, "the whole value");
    assert_eq!(captures(MatchKind::Regex, "(", "x", None), None, "a pattern that does not compile matches nothing");
    assert_eq!(captures(MatchKind::Id, "g-17", "Sales", Some("g-17")), Some(vec!["Sales".into()]));
    assert_eq!(captures(MatchKind::Id, "g-17", "Sales", None), None);
    assert_eq!(substitute("dept_$1 of $0, $9", &["v".into(), "x".into()]), "dept_x of v, ");
    assert_eq!(substitute("cost $", &[]), "cost $");
    assert_eq!(MatchKind::parse("regex"), Some(MatchKind::Regex));
    assert_eq!(MatchKind::parse("glob"), None);
    assert_eq!(MatchKind::Prefix.as_str(), "prefix");
}

/// [labac] groups, labels with levels and the lowest ceiling; the version kept while the
/// access is the same, the next when it changes
#[test]
fn a_subject_is_made_of_the_claims_and_versioned_by_its_access() {
    let rules = vec![
        Rule { group: Some("staff".into()), ..rule(1, "groups", MatchKind::Name, "employees") },
        Rule { label_key: Some("department".into()), label_value: Some("$1".into()), level: 3,
            ..rule(2, "groups", MatchKind::Prefix, "dept-") },
        Rule { group: Some("$1".into()), ceiling: Some(4), ..rule(3, "role", MatchKind::Regex, "app-(admin|ops)") },
        Rule { source: "saml".into(), group: Some("saml-only".into()), ..rule(4, "groups", MatchKind::Name, "employees") },
        Rule { ceiling: Some(2), ..rule(5, "role", MatchKind::Name, "contractor") },
    ];
    let claims = vec![Claim::new("oidc", "groups", "employees"), Claim::new("oidc", "groups", "dept-sales"),
        Claim::new("oidc", "role", "app-ops")];
    let s = map_subject(uid(), &rules, &claims, None);
    assert_eq!(s.groups, ["ops", "staff"].iter().map(|g| g.to_string()).collect());
    assert_eq!(s.labels.iter().cloned().collect::<Vec<_>>(), vec![Label { key: "department".into(), value: "sales".into(), level: 3 }]);
    assert_eq!((s.ceiling, s.version, s.rules.clone()), (Some(4), 1, vec![1, 2, 3]));
    let again = map_subject(uid(), &rules, &claims, Some(&s));
    assert_eq!(again.version, 1, "the same access: the same version");
    let mut more = claims.clone();
    more.push(Claim::new("oidc", "role", "contractor"));
    let changed = map_subject(uid(), &rules, &more, Some(&s));
    assert_eq!((changed.ceiling, changed.version), (Some(2), 2), "the lowest ceiling, the next version");
}

fn acl() -> Acl {
    let mut a = Acl::default();
    a.add_resource(Resource { kind: "schema".into(), id: "app".into(), ..Default::default() });
    a.add_resource(Resource { kind: "table".into(), id: "orders".into(), parent: Some(("schema".into(), "app".into())),
        labels: [("department".to_string(), "sales".to_string())].into_iter().collect(), private: false });
    a.add_resource(Resource { kind: "table".into(), id: "hr".into(), parent: Some(("schema".into(), "app".into())),
        labels: [("department".to_string(), "hr".to_string())].into_iter().collect(), private: true });
    a.add_resource(Resource { kind: "table".into(), id: "loop".into(), parent: Some(("table".into(), "loop".into())),
        ..Default::default() });
    a.add_entry(Entry { id: 1, kind: "schema".into(), resource: "app".into(), group: "staff".into(), level: 1, shared: true, ..Default::default() });
    a.add_entry(Entry { id: 2, kind: "schema".into(), resource: "app".into(), group: "ops".into(), level: 6, shared: false, ..Default::default() });
    a.add_entry(Entry { id: 3, kind: "table".into(), resource: "orders".into(), group: "*".into(), label: Some("department".into()), level: 5, ..Default::default() });
    a.add_entry(Entry { id: 4, kind: "table".into(), resource: "hr".into(), group: "staff".into(), label: Some("department=hr".into()), level: 2, ..Default::default() });
    a
}

fn subject(groups: &[&str], labels: &[(&str, &str, i16)], ceiling: Option<i16>) -> Subject {
    Subject { user_id: uid(), groups: groups.iter().map(|g| g.to_string()).collect(),
        labels: labels.iter().map(|(k, v, l)| Label { key: k.to_string(), value: v.to_string(), level: *l }).collect(),
        ceiling, version: 1, rules: vec![], ..Default::default() }
}

/// [labac] the highest entry on the resource or shared down; a private one only its own; a
/// label through which an entry matched caps it; the ceiling caps it all; 0 denies
#[test]
fn levels_come_from_the_resource_and_its_shared_parents() {
    let a = acl();
    let sales = subject(&["staff"], &[("department", "sales", 3)], None);
    let w = a.level(&sales, "table", "orders");
    assert_eq!((w.level, w.entry, w.label.as_deref()), (3, Some(3), Some("department=sales")), "entry 5 capped by the label's 3");
    assert_eq!(a.level(&sales, "table", "hr").level, 0, "private: the schema's shared entry does not reach it");
    let hr = subject(&["staff"], &[("department", "hr", 0)], None);
    assert_eq!(a.level(&hr, "table", "hr").level, 2, "a literal label condition, level 0 no cap");
    assert_eq!(a.level(&hr, "table", "orders").level, 1, "the schema's staff entry, shared down");
    let ops = subject(&["ops"], &[], Some(4));
    let w = a.level(&ops, "schema", "app");
    assert_eq!((w.level, w.capped), (4, true), "the ceiling");
    assert_eq!(a.level(&ops, "table", "orders").level, 0, "ops' entry is not shared");
    assert_eq!(a.level(&sales, "table", "loop").level, 0, "a loop of parents ends");
    assert_eq!(a.level(&sales, "table", "none").level, 0, "no such resource");
}

#[test]
fn actions_reach_and_predicate() {
    let mut a = acl();
    let sales = subject(&["staff"], &[("department", "sales", 3)], None);
    assert!(a.allowed(&sales, "table", "orders", "update"), "3 >= update's 3");
    assert!(!a.allowed(&sales, "table", "orders", "delete"));
    assert!(!a.allowed(&sales, "table", "orders", "fly"), "an action with no level");
    a.actions.insert(("table".into(), "fly".into()), 1);
    assert!(a.allowed(&sales, "table", "orders", "fly"), "the kind's own map");
    assert_eq!(a.reach(&sales, "table", "select"), vec!["orders".to_string()]);
    assert_eq!(a.predicate(&sales, "table", "select", "\"id\"", 2),
        Predicate { sql: "\"id\" = ANY($2)".into(), params: vec![vec!["orders".into()]] });
    let nobody = subject(&[], &[], None);
    assert_eq!(a.predicate(&nobody, "table", "select", "id", 1).sql, "FALSE");
    // [labac] soft_delete 4, delete 5, ddl 6; cleanup dropped (a purge is a delete)
    assert_eq!(default_action_level("cleanup"), None);
    assert_eq!(ACTIONS.iter().map(|a| default_action_level(a).unwrap()).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
}

/// [labac] a token carries the account and the version; another key, or an expired one, fails
#[test]
fn a_token_carries_the_subject_and_its_version() {
    let s = subject(&["staff"], &[], None);
    let t = issue(b"key", &Subject { version: 7, ..s.clone() }, 60).unwrap();
    assert_eq!(verify(b"key", &t).unwrap(), (uid(), 7));
    assert!(verify(b"other", &t).is_err());
    let old = jsonwebtoken::encode(&jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &TokenClaims { sub: uid().to_string(), ver: 1, iat: 0, exp: 1, lv: BTreeMap::new() },
        &jsonwebtoken::EncodingKey::from_secret(b"key").unwrap()).unwrap();
    assert!(verify(b"key", &old).is_err(), "expired");
}

struct Seen(std::sync::Mutex<Vec<(Uuid, i64)>>);

impl SubjectHook for Seen {
    fn changed(&self, user_id: Uuid, version: i64) {
        self.0.lock().unwrap().push((user_id, version));
    }
}

/// [labac] in the database: rules added, a subject remapped and stored, its version told to
/// the hook once per change; the ACL loaded back; a token current until the subject moves on
#[tokio::test]
async fn subjects_and_the_acl_in_the_database() {
    let Some(pool) = crate::test_pool("labac").await else { return };
    let _rules = RULES_TABLE.lock().await;
    sqlx::query("DELETE FROM labac_rules").execute(&pool).await.unwrap();
    let user = Uuid::new_v4();
    let seen = Arc::new(Seen(std::sync::Mutex::new(Vec::new())));
    set_hook(seen.clone());
    add_rule(&pool, &Rule { group: Some("staff".into()), ..rule(0, "groups", MatchKind::Name, "employees") }).await.unwrap();
    assert!(add_rule(&pool, &rule(0, "groups", MatchKind::Regex, "(")).await.is_err(), "a pattern that does not compile");
    let s = remap(&pool, user, &[Claim::new("oidc", "groups", "employees")]).await.unwrap();
    assert_eq!((s.version, s.groups.len()), (1, 1));
    assert_eq!(super::subject(&pool, user).await.unwrap(), Some(s.clone()));
    let t = issue(b"k", &s, 60).unwrap();
    assert_eq!(current(&pool, b"k", &t).await.unwrap(), Some(s.clone()));
    remap(&pool, user, &[Claim::new("oidc", "groups", "employees")]).await.unwrap();
    let s2 = remap(&pool, user, &[]).await.unwrap();
    assert_eq!(s2.version, 2);
    assert_eq!(current(&pool, b"k", &t).await.unwrap(), None, "stale");
    assert_eq!(seen.0.lock().unwrap().iter().filter(|(u, _)| *u == user).cloned().collect::<Vec<_>>(), vec![(user, 1), (user, 2)]);
    let kind = format!("k{}", user.simple());
    put_resource(&pool, &Resource { kind: kind.clone(), id: "a".into(), labels: [("x".to_string(), "1".to_string())].into_iter().collect(),
        ..Default::default() }).await.unwrap();
    add_entry(&pool, &Entry { kind: kind.clone(), resource: "a".into(), group: "*".into(), level: 2, ..Default::default() }).await.unwrap();
    set_action(&pool, &kind, "select", 2).await.unwrap();
    let acl = load_acl(&pool).await.unwrap();
    assert!(acl.allowed(&s2, &kind, "a", "select"));
    assert_eq!(acl.resources[&(kind.clone(), "a".to_string())].labels["x"], "1");
}

/// [labac] an id_token's groups claim, an array or one string, becomes the rules' input
#[cfg(feature = "oauth")]
#[test]
fn an_id_tokens_groups_become_claims() {
    let c: crate::jwt::IdClaims = serde_json::from_value(serde_json::json!({"sub": "1", "groups": ["a", "b", 3]})).unwrap();
    assert_eq!(claims_of_oidc(&c), vec![Claim::new("oidc", "groups", "a"), Claim::new("oidc", "groups", "b")]);
    let c: crate::jwt::IdClaims = serde_json::from_value(serde_json::json!({"sub": "1", "groups": "solo"})).unwrap();
    assert_eq!(c.groups, vec!["solo".to_string()]);
    let c: crate::jwt::IdClaims = serde_json::from_value(serde_json::json!({"sub": "1"})).unwrap();
    assert!(c.groups.is_empty());
}

/// [labac] HMAC-SHA256 as RFC 4231 has it, a long key included
#[test]
fn hmac_is_rfc_4231s() {
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    assert_eq!(hex(hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq!(hex(hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

/// [labac] the SQL half: a token ytproxy signed holds its ids for the transaction; another
/// key's, a changed one, an expired one are refused. Skipped where the extension cannot be made.
#[tokio::test]
async fn the_sql_half_takes_only_a_token_ytproxy_signed() {
    let Some(pool) = crate::test_pool("labac-sql").await else { return };
    if let Err(e) = apply_sql(&pool, b"proxy-key").await {
        eprintln!("labac SQL skipped: {e}");
        return;
    }
    let ids: BTreeMap<String, Vec<String>> = [("table:select".to_string(), vec!["orders".to_string(), "items".to_string()])].into_iter().collect();
    let t = enter_token(b"proxy-key", uid(), &ids, 60);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT labac.enter($1)").bind(&t).execute(&mut *tx).await.unwrap();
    let (got,): (Vec<String>,) = sqlx::query_as("SELECT labac.ids('table', 'select')").fetch_one(&mut *tx).await.unwrap();
    assert_eq!(got, vec!["orders".to_string(), "items".to_string()]);
    let (none,): (Vec<String>,) = sqlx::query_as("SELECT labac.ids('table', 'delete')").fetch_one(&mut *tx).await.unwrap();
    assert!(none.is_empty());
    tx.commit().await.unwrap();
    let (after,): (Vec<String>,) = sqlx::query_as("SELECT labac.ids('table', 'select')").fetch_one(&pool).await.unwrap();
    assert!(after.is_empty(), "for its transaction only");
    // an expired one, signed right: enter_token gives at least a second
    let expired = {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(serde_json::json!({ "sub": uid().to_string(), "exp": 1, "ids": ids }).to_string());
        let sig: String = hmac_sha256(b"proxy-key", payload.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}.{}", payload, sig)
    };
    for bad in [enter_token(b"other", uid(), &ids, 60), format!("{}x", t), expired] {
        assert!(sqlx::query("SELECT labac.enter($1)").bind(&bad).execute(&pool).await.is_err(), "{bad}");
    }
}

/// [review 2026-11-21] an entry shared down with a bare label is judged by the child's label,
/// not the parent's
#[test]
fn a_shared_label_entry_is_judged_by_the_childs_label() {
    let mut a = Acl::default();
    a.add_resource(Resource { kind: "dept".into(), id: "p".into(), labels: [("department".to_string(), "sales".to_string())].into_iter().collect(), ..Default::default() });
    a.add_resource(Resource { kind: "doc".into(), id: "c".into(), parent: Some(("dept".into(), "p".into())),
        labels: [("department".to_string(), "finance".to_string())].into_iter().collect(), private: false });
    a.add_entry(Entry { id: 1, kind: "dept".into(), resource: "p".into(), group: "*".into(), label: Some("department".into()), level: 3, shared: true, user_id: None });
    let sales = subject(&[], &[("department", "sales", 0)], None);
    let finance = subject(&[], &[("department", "finance", 0)], None);
    assert_eq!(a.level(&sales, "doc", "c").level, 0, "the child is finance's");
    assert_eq!(a.level(&finance, "doc", "c").level, 3);
    assert_eq!(a.level(&sales, "dept", "p").level, 3, "the parent itself is sales'");
}

/// [review 2026-11-21] two remaps of one account at once: each version once, each told once;
/// a rule that does not read fails the remap; a stored body that does not read goes on from its version
#[tokio::test]
async fn remaps_one_at_a_time_and_rules_that_do_not_read() {
    let Some(pool) = crate::test_pool("labac-race").await else { return };
    let _rules = RULES_TABLE.lock().await;
    sqlx::query("DELETE FROM labac_rules").execute(&pool).await.unwrap();
    add_rule(&pool, &Rule { group: Some("$0".into()), ..rule(0, "groups", MatchKind::Prefix, "") }).await.unwrap();
    let user = Uuid::new_v4();
    let seen = Arc::new(Seen(std::sync::Mutex::new(Vec::new())));
    set_hook(seen.clone());
    let (p1, p2) = (pool.clone(), pool.clone());
    let a = tokio::spawn(async move { remap(&p1, user, &[Claim::new("oidc", "groups", "a")]).await.unwrap().version });
    let b = tokio::spawn(async move { remap(&p2, user, &[Claim::new("oidc", "groups", "b")]).await.unwrap().version });
    let mut got = vec![a.await.unwrap(), b.await.unwrap()];
    got.sort();
    assert_eq!(got, vec![1, 2], "no two states share a version");
    let mut told: Vec<i64> = seen.0.lock().unwrap().iter().filter(|(u, _)| *u == user).map(|(_, v)| *v).collect();
    told.sort();
    assert_eq!(told, vec![1, 2], "each told once");
    // a stored body that does not read: the next version past it
    sqlx::query("UPDATE labac_subjects SET version = 5, body = 'not json' WHERE user_id = $1").bind(user).execute(&pool).await.unwrap();
    assert_eq!(remap(&pool, user, &[Claim::new("oidc", "groups", "a")]).await.unwrap().version, 6);
    // a rule of no match kind - where the table has no CHECK yet - fails the remap
    if sqlx::query("INSERT INTO labac_rules (source, claim, match_kind, pattern) VALUES ('*', 'groups', 'glob', '*')")
        .execute(&pool).await.is_ok() {
        assert!(remap(&pool, user, &[]).await.is_err());
    }
    sqlx::query("DELETE FROM labac_rules").execute(&pool).await.unwrap();
}

/// [review 2026-11-21] the SQL half trusts no subject a session sets itself, nor a token with no expiry
#[tokio::test]
async fn the_sql_half_takes_no_subject_a_session_sets_itself() {
    let Some(pool) = crate::test_pool("labac-sql2").await else { return };
    if apply_sql(&pool, b"proxy-key").await.is_err() {
        return;
    }
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('labac.subject', '{\"ids\": {\"table:select\": [\"*\"]}}', true)").execute(&mut *tx).await.unwrap();
    let (got,): (Vec<String>,) = sqlx::query_as("SELECT labac.ids('table', 'select')").fetch_one(&mut *tx).await.unwrap();
    assert!(got.is_empty(), "a subject set by hand is none");
    tx.rollback().await.unwrap();
    let no_exp = {
        use base64::Engine;
        let payload = base64::engine::general_purpose::STANDARD.encode(serde_json::json!({ "sub": "x", "ids": {} }).to_string());
        let sig: String = hmac_sha256(b"proxy-key", payload.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect();
        format!("{}.{}", payload, sig)
    };
    assert!(sqlx::query("SELECT labac.enter($1)").bind(&no_exp).execute(&pool).await.is_err(), "no expiry");
}

/// [labac] a person's own entry counts for that person only, and only while
/// the person is in its group; a rule's pg_role goes to the subject in rule order, and a change
/// of them is a change of access
#[test]
fn a_persons_entry_and_the_roles_the_rules_give() {
    let mut a = acl();
    let alice = subject(&["staff"], &[], None);
    let bob = Subject { user_id: Uuid::new_v4(), ..subject(&["staff"], &[], None) };
    a.add_entry(Entry { id: 9, kind: "table".into(), resource: "orders".into(), group: "staff".into(), user_id: Some(alice.user_id),
        level: 4, ..Default::default() });
    assert_eq!(a.level(&alice, "table", "orders").level, 4, "her own entry");
    assert!(a.allowed(&alice, "table", "orders", "soft_delete") && !a.allowed(&alice, "table", "orders", "delete"));
    assert_eq!(a.level(&bob, "table", "orders").level, 1, "not bob's: the schema's shared staff entry");
    let left = subject(&[], &[], None);
    assert_eq!(a.level(&left, "table", "orders").level, 0, "out of the group: her entry no more");
    let rules = vec![
        Rule { group: Some("sales".into()), pg_role: Some("sales".into()), ..rule(1, "groups", MatchKind::Name, "Sales-EU") },
        Rule { group: Some("ops".into()), pg_role: Some("ops_$1".into()), ..rule(2, "groups", MatchKind::Regex, "Admins-(.*)") },
        Rule { pg_role: Some("sales".into()), ..rule(3, "groups", MatchKind::Name, "Sales-US") },
    ];
    let claims = [Claim::new("oidc", "groups", "Admins-eu"), Claim::new("oidc", "groups", "Sales-EU"), Claim::new("oidc", "groups", "Sales-US")];
    let s = map_subject(uid(), &rules, &claims, None);
    assert_eq!(s.pg_roles, vec!["sales".to_string(), "ops_eu".to_string()], "rule order, once each");
    let fewer = map_subject(uid(), &rules[..1], &claims, Some(&s));
    assert_eq!(fewer.version, s.version + 1, "a role less is a change of access");
}

/// [labac] the person's token page: no key no page; no subject 403; else a token for the
/// subject's version, the JSON or the page with it
#[tokio::test]
async fn the_token_page() {
    use axum::http::StatusCode;
    let now = chrono::Utc::now();
    let off = crate::config::Config::new("Acme", "https://acme.test");
    assert_eq!(crate::routes::labac_token_answer(&off, None, true, now).status(), StatusCode::NOT_FOUND);
    let on = off.clone().with_labac(LabacConfig { token_key: Some(b"key".to_vec()), token_ttl: Some(std::time::Duration::from_secs(600)),
        ..Default::default() });
    assert_eq!(crate::routes::labac_token_answer(&on, None, true, now).status(), StatusCode::FORBIDDEN);
    let none = crate::routes::labac_token_answer(&on, None, false, now);
    assert_eq!(none.status(), StatusCode::FORBIDDEN);
    let s = Subject { version: 3, ..subject(&["staff"], &[], None) };
    let r = crate::routes::labac_token_answer(&on, Some(&s), true, now);
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["cache-control"], "no-store");
    let body: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(verify(b"key", body["token"].as_str().unwrap()).unwrap(), (s.user_id, 3));
    assert_eq!(body["version"], 3);
    assert!(body["expires_at"].as_str().unwrap().starts_with(&(now + chrono::Duration::seconds(600)).format("%Y-%m-%dT%H:%M").to_string()));
    let page = crate::routes::labac_token_answer(&on, Some(&s), false, now);
    let html = String::from_utf8(axum::body::to_bytes(page.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
    assert!(html.contains("<textarea id=\"t\" readonly") && html.contains("navigator.clipboard"), "{html}");
}

/// [labac] a person's entry and a rule's pg_role in the database
#[tokio::test]
async fn a_persons_entry_and_a_rules_role_in_the_database() {
    let Some(pool) = crate::test_pool("labac").await else { return };
    let _rules = RULES_TABLE.lock().await;
    let user = Uuid::new_v4();
    let kind = format!("p{}", user.simple());
    put_resource(&pool, &Resource { kind: kind.clone(), id: "a".into(), ..Default::default() }).await.unwrap();
    add_entry(&pool, &Entry { kind: kind.clone(), resource: "a".into(), group: "g".into(), user_id: Some(user), level: 5,
        ..Default::default() }).await.unwrap();
    let acl = load_acl(&pool).await.unwrap();
    let e = &acl.entries[&(kind.clone(), "a".to_string())][0];
    assert_eq!((e.user_id, e.level), (Some(user), 5));
    let me = Subject { user_id: user, groups: ["g".to_string()].into_iter().collect(), ..Default::default() };
    assert!(acl.allowed(&me, &kind, "a", "delete"));
    let id = add_rule(&pool, &Rule { pg_role: Some(format!("r{}", user.simple())), ..rule(0, "groups", MatchKind::Name, &kind) }).await.unwrap();
    let got = rules(&pool).await.unwrap().into_iter().find(|r| r.id == id).unwrap();
    assert_eq!(got.pg_role, Some(format!("r{}", user.simple())));
    sqlx::query("DELETE FROM labac_rules WHERE id = $1").bind(id).execute(&pool).await.unwrap();
}

/// [opa] OPA's level raises or lowers signon's for the resources it names, the ceiling caps it,
/// it is asked once per subject version and kind, and an OPA that fails grants nothing
#[cfg(feature = "opa")]
#[tokio::test]
async fn opa_gives_the_levels_of_its_kinds() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let asked = Arc::new(AtomicUsize::new(0));
    let seen = asked.clone();
    let app = axum::Router::new().route("/v1/data/labac/levels", axum::routing::post(move |axum::Json(b): axum::Json<serde_json::Value>| {
        let seen = seen.clone();
        async move {
            seen.fetch_add(1, Ordering::SeqCst);
            assert_eq!(b["input"]["kind"], "table");
            assert!(b["input"]["resources"].as_array().unwrap().iter().any(|r| r["id"] == "orders" && r["parent"]["id"] == "app"));
            if b["input"]["subject"]["groups"].as_array().unwrap().iter().any(|g| g == "broken") {
                return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::Json(serde_json::json!({})));
            }
            if b["input"]["subject"]["groups"].as_array().unwrap().iter().any(|g| g == "undefined") {
                return (axum::http::StatusCode::OK, axum::Json(serde_json::json!({})));
            }
            (axum::http::StatusCode::OK, axum::Json(serde_json::json!({ "result": { "orders": 0, "hr": 6 } })))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let opa = Opa::new(format!("http://{addr}/v1/data/labac/levels"), vec!["table".into()], std::time::Duration::from_secs(60)).unwrap();
    let a = acl();
    let staff = subject(&["staff"], &[("department", "sales", 3)], None);
    assert_eq!(a.reach(&staff, "table", "select"), vec!["orders".to_string()], "signon alone");
    assert_eq!(opa.reach(&a, &staff, "table", "select").await.unwrap(), vec!["hr".to_string()], "lowered and raised");
    assert_eq!(opa.reach(&a, &staff, "table", "delete").await.unwrap(), vec!["hr".to_string()]);
    assert_eq!(asked.load(Ordering::SeqCst), 1, "once per version and kind");
    let capped = Subject { version: 2, ..subject(&["staff"], &[], Some(2)) };
    assert_eq!(opa.reach(&a, &capped, "table", "update").await.unwrap(), Vec::<String>::new(), "the ceiling caps OPA's 6");
    assert_eq!(asked.load(Ordering::SeqCst), 2, "a new version asks again");
    assert_eq!(opa.reach(&a, &staff, "schema", "select").await.unwrap(), vec!["app".to_string()], "a kind OPA is not set for");
    assert_eq!(asked.load(Ordering::SeqCst), 2);
    let broken = Subject { version: 5, ..subject(&["broken"], &[], None) };
    assert!(opa.reach(&a, &broken, "table", "select").await.is_err(), "no answer: an error");
    // [review 2026-11-21] no result is no answer; one resource asked about; a resource added asks again
    let undefined = Subject { version: 6, ..subject(&["undefined"], &[], None) };
    assert!(opa.reach(&a, &undefined, "table", "select").await.is_err(), "no result: an error");
    assert!(opa.allowed(&a, &staff, "table", "hr", "delete").await.unwrap(), "OPA's 6 on one resource");
    assert!(!opa.allowed(&a, &staff, "table", "orders", "select").await.unwrap(), "OPA's 0");
    let before = asked.load(Ordering::SeqCst);
    let mut more = acl();
    more.add_resource(Resource { kind: "table".into(), id: "new".into(), parent: Some(("schema".into(), "app".into())), ..Default::default() });
    let _ = opa.reach(&more, &staff, "table", "select").await.unwrap();
    assert_eq!(asked.load(Ordering::SeqCst), before + 1, "the resources changed: asked again");
}


/// [review 2026-11-21] an empty key signs and checks nothing; a token's life is capped; an enter
/// token made for a role is that role's only
#[tokio::test]
async fn an_empty_key_and_a_role_bound_enter_token() {
    let s = subject(&["staff"], &[], None);
    assert!(issue(b"", &s, 60).is_err());
    assert!(verify(b"", "a.b.c").is_err());
    let t = issue(b"k", &s, i64::MAX).unwrap();
    assert!(verify(b"k", &t).is_ok(), "a huge ttl is capped, not overflowed");
    let off = crate::config::Config::new("Acme", "https://acme.test").with_labac(LabacConfig { token_key: Some(Vec::new()), ..Default::default() });
    assert_eq!(crate::routes::labac_token_answer(&off, Some(&s), true, chrono::Utc::now()).status(), axum::http::StatusCode::NOT_FOUND);
    let Some(pool) = crate::test_pool("labac-role").await else { return };
    if apply_sql(&pool, b"proxy-key").await.is_err() {
        return;
    }
    let ids: BTreeMap<String, Vec<String>> = [("dept:select".to_string(), vec!["sales".to_string()])].into_iter().collect();
    let me: String = sqlx::query_scalar("SELECT session_user::text").fetch_one(&pool).await.unwrap();
    let mine = enter_token_for(b"proxy-key", uid(), &me, &ids, 60);
    let theirs = enter_token_for(b"proxy-key", uid(), "somebody_else", &ids, 60);
    let ok: bool = sqlx::query_scalar("SELECT labac.checked($1) IS NOT NULL").bind(&mine).fetch_one(&pool).await.unwrap();
    assert!(ok, "the login's own role");
    let no: bool = sqlx::query_scalar("SELECT labac.checked($1) IS NULL").bind(&theirs).fetch_one(&pool).await.unwrap();
    assert!(no, "another role's token is no subject here");
}

/// [levels] a rule gives a named level - the highest of the rules that match, a capture of the claim
/// as its value; a person's own row stands over them; what is no level gives none; a change of a
/// level is a change of access (the version moves); a body stored before the levels reads with none
#[test]
fn rules_and_a_persons_row_give_named_levels() {
    let rules = vec![
        Rule { level_name: Some("sal".into()), level_value: Some("$1".into()), ..rule(1, "clearance", MatchKind::Regex, "^L([0-9]+)$") },
        Rule { level_name: Some("sal".into()), level_value: Some("2".into()), ..rule(2, "groups", MatchKind::Name, "staff") },
        Rule { level_name: Some("review".into()), level_value: Some("3".into()), ..rule(3, "groups", MatchKind::Name, "reviewers") },
        Rule { level_name: Some("sal".into()), level_value: Some("$1".into()), ..rule(4, "badge", MatchKind::Regex, "^(.*)$") },
        Rule { level_name: Some("bad name".into()), level_value: Some("5".into()), ceiling: Some(1), ..rule(5, "groups", MatchKind::Name, "staff") },
    ];
    let user = uid();
    let claims = [Claim::new("saml", "clearance", "L5"), Claim::new("oidc", "groups", "staff"), Claim::new("oidc", "groups", "reviewers"),
        Claim::new("oidc", "badge", "-4"), Claim::new("oidc", "badge", "seven")];
    let s = map_subject(user, &rules, &claims, None);
    assert_eq!(s.levels, [("review".to_string(), 3), ("sal".to_string(), 5)].into_iter().collect(), "the highest matched; -4, seven and a bad name give none");
    assert_eq!((s.rule_levels.clone(), s.ceiling), (s.levels.clone(), Some(1)), "the ceiling is the action scale's: it caps no named level");
    // a person's own rows stand over the rules, lower or higher, name by name
    let person: BTreeMap<String, i16> = [("sal".to_string(), 2), ("audit".to_string(), 4)].into_iter().collect();
    let p = map_subject_with(user, &rules, &claims, &person, Some(&s));
    assert_eq!(p.levels, [("audit".to_string(), 4), ("review".to_string(), 3), ("sal".to_string(), 2)].into_iter().collect());
    assert_eq!((p.rule_levels.get("sal"), p.version), (Some(&5), s.version + 1), "what the rules gave is kept; the access changed");
    assert_eq!(map_subject_with(user, &rules, &claims, &person, Some(&p)).version, p.version, "the same again: the same version");
    assert_eq!(effective_levels(&s.rule_levels, &BTreeMap::new()), s.rule_levels);
    // a subject stored before the levels
    let old = r#"{"user_id":"00000000-0000-0000-0000-000000000001","groups":["staff"],"labels":[],"ceiling":null,"version":7,"rules":[1],"pg_roles":[]}"#;
    let read: Subject = serde_json::from_str(old).expect("a body of the version before");
    assert!(read.levels.is_empty() && read.rule_levels.is_empty() && read.version == 7);
    assert!(level_name_ok("sal") && level_name_ok("review_2") && !level_name_ok("") && !level_name_ok("a.b") && !level_name_ok("a b"));
}

/// [levels] what a call asks against the person's own: from 0 to its own, never above; an unknown
/// name's own is 0; a query string says `level` (sal) and `level.<name>`
#[test]
fn the_levels_a_call_asks() {
    let own: BTreeMap<String, i16> = [("sal".to_string(), 5), ("review".to_string(), 2)].into_iter().collect();
    let ask = |q: &str| asked_from_query(q).and_then(|a| asked_levels(&own, &a));
    assert_eq!(ask(""), Ok(BTreeMap::new()), "nothing asked: no top");
    assert_eq!(ask("level=2"), Ok([("sal".to_string(), 2)].into_iter().collect()));
    assert_eq!(ask("x=1&level.sal=5&level.review=0"), Ok([("review".to_string(), 0), ("sal".to_string(), 5)].into_iter().collect()), "its own, and 0");
    for above in ["level=6", "level.review=3", "level.audit=1", "level.sal=-1"] {
        assert!(ask(above).unwrap_err().contains("above your own"), "{above}");
    }
    for bad in ["level=two", "level.sal=", "level.a.b=1", "level.=1", "level.sal=99999"] {
        assert!(ask(bad).is_err(), "{bad}");
    }
    // [review 2026-11-22] written percent-encoded it is the same ask; a key that starts as a level's
    // and is none is refused, not passed by with the person's full level
    assert_eq!(ask("level%2Esal=2"), Ok([("sal".to_string(), 2)].into_iter().collect()));
    assert_eq!(ask("level=%32"), Ok([("sal".to_string(), 2)].into_iter().collect()));
    for bad in ["level%3D0", "levels=1", "level_sal=1", "level%2Esal=9"] {
        assert!(ask(bad).is_err(), "{bad}");
    }
}

/// [levels] an entry on resource `*` is for every resource of the kind - private ones and ids with
/// no row too: `any` says so for an action, `level`, `allowed` and `reach` agree for the resources
/// there are; the ceiling caps it; an entry that reads the resource's own label is of one resource
#[test]
fn an_entry_on_every_resource() {
    let mut acl = Acl::default();
    for (id, parent, private) in [("a", None, false), ("sales", Some("a"), false), ("hr", Some("a"), true)] {
        acl.add_resource(Resource { kind: "dept".into(), id: id.into(), parent: parent.map(|p| ("dept".to_string(), p.to_string())),
            private, ..Default::default() });
    }
    acl.add_entry(Entry { id: 1, kind: "dept".into(), resource: ANY.into(), group: "reviewers".into(), level: 1, ..Default::default() });
    acl.add_entry(Entry { id: 2, kind: "dept".into(), resource: "sales".into(), group: "sales".into(), level: 3, ..Default::default() });
    acl.add_entry(Entry { id: 3, kind: "dept".into(), resource: ANY.into(), group: "staff".into(), label: Some("region".into()), level: 5, ..Default::default() });
    acl.add_entry(Entry { id: 4, kind: "project".into(), resource: ANY.into(), group: "*".into(), user_id: Some(Uuid::nil()), level: 6, ..Default::default() });
    let reviewer = subject(&["reviewers"], &[], None);
    assert!(acl.any(&reviewer, "dept", "select") && !acl.any(&reviewer, "dept", "update") && !acl.any(&reviewer, "project", "select"));
    assert_eq!(acl.reach(&reviewer, "dept", "select"), vec!["a", "hr", "sales"], "the private one too: the entry is its own");
    assert!(acl.allowed(&reviewer, "dept", "hr", "select") && !acl.allowed(&reviewer, "dept", "hr", "insert"));
    assert_eq!(acl.level(&reviewer, "dept", "hr").on, Some(("dept".to_string(), "*".to_string())));
    let sales = subject(&["sales"], &[], None);
    assert!(!acl.any(&sales, "dept", "select"), "an entry on one resource is no entry on all");
    assert_eq!(acl.reach(&sales, "dept", "update"), vec!["sales"]);
    let capped = subject(&["reviewers"], &[], Some(0));
    assert!(!acl.any(&capped, "dept", "select") && acl.reach(&capped, "dept", "select").is_empty(), "the ceiling caps it");
    let staff = subject(&["staff"], &[("region", "emea", 0)], None);
    assert!(!acl.any(&staff, "dept", "select"), "the resource's label is of one resource: no answer for all");
    let one = Subject { user_id: Uuid::nil(), ..subject(&["x"], &[], None) };
    assert!(acl.any(&one, "project", "ddl") && !acl.any(&reviewer, "project", "select"), "a person's own entry on all");
    assert_eq!(acl.any_level(&reviewer, "dept"), 1);
}

/// [levels] a token minted for levels carries them as its tops; one with none - one issued before the
/// levels too - has no top; the enter token ytproxy signs says the pairs open to any id apart from the
/// ids, and the levels
#[test]
fn tokens_and_levels() {
    let s = Subject { version: 4, ..subject(&["staff"], &[], None) };
    let tops: BTreeMap<String, i16> = [("sal".to_string(), 3)].into_iter().collect();
    let t = issue_at(b"k", &s, 60, &tops).unwrap();
    assert_eq!(verify_levels(b"k", &t).unwrap(), (s.user_id, 4, tops.clone()));
    assert_eq!(verify(b"k", &t).unwrap(), (s.user_id, 4));
    let plain = issue(b"k", &s, 60).unwrap();
    assert_eq!(verify_levels(b"k", &plain).unwrap().2, BTreeMap::new(), "no top");
    assert!(!String::from_utf8_lossy(&{ use base64::Engine; base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(plain.split('.').nth(1).unwrap()).unwrap() })
        .contains("\"lv\""), "a token with no top is the token of the version before");
    let ids: BTreeMap<String, Vec<String>> = [("dept:select".to_string(), vec!["sales".to_string()])].into_iter().collect();
    let e = enter_token_with(b"k", s.user_id, Some("sales"), &ids, &["project:select".to_string()], &tops, 60);
    let body: serde_json::Value = { use base64::Engine;
        serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(e.split('.').next().unwrap()).unwrap()).unwrap() };
    assert_eq!((body["ids"]["dept:select"][0].as_str(), body["any"][0].as_str(), body["levels"]["sal"].as_i64(), body["role"].as_str()),
        (Some("sales"), Some("project:select"), Some(3), Some("sales")));
    assert!(enter_token_with(b"k", s.user_id, None, &ids, &[], &BTreeMap::new(), 60).split('.').count() == 2);
}

/// [levels] the token page for the levels asked: minted for them when they are the person's own or
/// lower, refused above; the answer says the levels it carries
#[tokio::test]
async fn the_token_page_and_the_levels_asked() {
    use axum::http::StatusCode;
    let now = chrono::Utc::now();
    let on = crate::config::Config::new("Acme", "https://acme.test").with_labac(LabacConfig { token_key: Some(b"key".to_vec()), ..Default::default() });
    let mut s = Subject { version: 2, ..subject(&["staff"], &[], None) };
    s.levels.insert("sal".into(), 4);
    let own = s.levels.clone();
    let r = crate::routes::labac_token_answer_at(&on, Some(&s), &own, asked_from_query("level=3"), true, now);
    assert_eq!(r.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["levels"]["sal"], 3);
    assert_eq!(verify_levels(b"key", body["token"].as_str().unwrap()).unwrap().2.get("sal"), Some(&3));
    for (q, json) in [("level=5", true), ("level.review=1", true), ("level=<b>", false)] {
        let r = crate::routes::labac_token_answer_at(&on, Some(&s), &own, asked_from_query(q), json, now);
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "{q}");
        let text = String::from_utf8(axum::body::to_bytes(r.into_body(), usize::MAX).await.unwrap().to_vec()).unwrap();
        assert!(!text.contains("<b>") && !text.contains("\"token\""), "{q}: {text}");
    }
    let plain = crate::routes::labac_token_answer(&on, Some(&s), true, now);
    let body: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(plain.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert!(verify_levels(b"key", body["token"].as_str().unwrap()).unwrap().2.is_empty(), "nothing asked: no top");
    assert_eq!(own_levels(&LabacConfig::default(), &s).await.unwrap(), own);
}

/// [levels] in the database: a rule with a level, a person's row over it - set, and taken away - each
/// a new version told to the hook at once, a row for an account with no subject kept for its first
/// sign-in; `*` is no resource's id
#[tokio::test]
async fn levels_in_the_database() {
    let Some(pool) = crate::test_pool("labac").await else { return };
    let _rules = RULES_TABLE.lock().await;
    sqlx::query("DELETE FROM labac_rules").execute(&pool).await.unwrap();
    let seen = Arc::new(Seen(std::sync::Mutex::new(Vec::new())));
    set_hook(seen.clone());
    let level = |name: &str, value: &str| Rule { level_name: Some(name.into()), level_value: Some(value.into()), ..rule(0, "clearance", MatchKind::Regex, "^L([0-9])$") };
    add_rule(&pool, &level("sal", "$1")).await.unwrap();
    for (n, v) in [("sal", "high"), ("s a l", "1"), ("sal", "-1")] {
        assert!(add_rule(&pool, &level(n, v)).await.is_err(), "{n} = {v}");
    }
    assert!(add_rule(&pool, &Rule { level_value: None, ..level("sal", "1") }).await.is_err(), "a name and a value, both");
    assert_eq!(rules(&pool).await.unwrap().iter().filter(|r| r.level_name.as_deref() == Some("sal")).count(), 1);
    let user = Uuid::new_v4();
    // a row before the person's first sign-in waits for it
    set_level(&pool, user, "audit", Some(2)).await.unwrap();
    assert_eq!(super::subject(&pool, user).await.unwrap(), None);
    let s = remap(&pool, user, &[Claim::new("saml", "clearance", "L5")]).await.unwrap();
    assert_eq!((s.levels.get("sal"), s.levels.get("audit"), s.version), (Some(&5), Some(&2), 1));
    // the person's own row over the rule's level: at once, a new version, told
    set_level(&pool, user, "sal", Some(3)).await.unwrap();
    let now = super::subject(&pool, user).await.unwrap().unwrap();
    assert_eq!((now.levels.get("sal"), now.rule_levels.get("sal"), now.version), (Some(&3), Some(&5), 2));
    assert_eq!(person_levels(&pool, user).await.unwrap().get("sal"), Some(&3));
    assert!(seen.0.lock().unwrap().contains(&(user, 2)));
    let t = issue(b"k", &s, 60).unwrap();
    assert_eq!(current(&pool, b"k", &t).await.unwrap(), None, "the token of the level before is stale");
    set_level(&pool, user, "sal", Some(3)).await.unwrap();
    assert_eq!(super::subject(&pool, user).await.unwrap().unwrap().version, 2, "the same again: nothing moves");
    // a sign-in keeps the row; taken away, the rule's level counts again
    assert_eq!(remap(&pool, user, &[Claim::new("saml", "clearance", "L5")]).await.unwrap().levels.get("sal"), Some(&3));
    set_level(&pool, user, "sal", None).await.unwrap();
    let back = super::subject(&pool, user).await.unwrap().unwrap();
    assert_eq!((back.levels.get("sal"), back.version), (Some(&5), 3));
    assert!(set_level(&pool, user, "s.l", Some(1)).await.is_err() && set_level(&pool, user, "sal", Some(-2)).await.is_err());
    // `*` is every resource of a kind, never one
    assert!(put_resource(&pool, &Resource { kind: "dept".into(), id: "*".into(), ..Default::default() }).await.is_err());
    assert!(put_resource(&pool, &Resource { kind: "dept".into(), id: "x".into(), parent: Some(("dept".into(), "*".into())), ..Default::default() }).await.is_err());
}

/// [approval] the approval scale: view 1 to override 6 unless a kind sets its own; a level gives
/// its action and the ones below it - to approve is not to veto - and 0, or no entry, none
#[test]
fn the_approval_scale() {
    assert_eq!(APPROVAL_ACTIONS.iter().map(|a| default_action_level(a).unwrap()).collect::<Vec<_>>(), vec![1, 2, 3, 4, 5, 6]);
    assert!(APPROVAL_ACTIONS.iter().all(|a| !ACTIONS.contains(a)), "no name of the one scale is the other's");
    assert_eq!(default_action_level("disapprove"), None, "an approval is not taken back: no such action");
    let mut acl = Acl::default();
    acl.add_resource(Resource { kind: "queue".into(), id: "payments".into(), ..Default::default() });
    acl.add_entry(Entry { id: 1, kind: "queue".into(), resource: "payments".into(), group: "approvers".into(), level: 4, ..Default::default() });
    acl.add_entry(Entry { id: 2, kind: "queue".into(), resource: "payments".into(), group: "officers".into(), level: 5, ..Default::default() });
    acl.add_entry(Entry { id: 3, kind: "queue".into(), resource: ANY.into(), group: "board".into(), level: 6, ..Default::default() });
    let of = |group: &str| Subject { user_id: Uuid::new_v4(), groups: [group.to_string()].into_iter().collect(), ..Default::default() };
    let may = |acl: &Acl, group: &str, action: &str| acl.allowed(&of(group), "queue", "payments", action);
    assert!(may(&acl, "approvers", "approve") && may(&acl, "approvers", "recommend") && may(&acl, "approvers", "view"));
    assert!(!may(&acl, "approvers", "veto") && !may(&acl, "approvers", "override"), "to approve is not to veto");
    assert!(may(&acl, "officers", "veto") && may(&acl, "officers", "approve") && !may(&acl, "officers", "override"));
    assert!(!may(&acl, "others", "view") && !may(&acl, "others", "approve"), "no entry: nothing");
    // an entry on every resource of the kind: the board, on a queue no resource row names too
    assert!(acl.any(&of("board"), "queue", "override") && acl.any_level(&of("board"), "queue") == 6);
    // a kind's own levels stand over the scale's
    acl.actions.insert(("queue".into(), "approve".into()), 5);
    assert!(!may(&acl, "approvers", "approve") && may(&acl, "officers", "approve"), "this kind asks 5 to approve");
    // the ceiling caps it as any level
    let capped = Subject { ceiling: Some(3), ..of("officers") };
    assert!(acl.allowed(&capped, "queue", "payments", "recommend") && !acl.allowed(&capped, "queue", "payments", "veto"));
}
