//! [permissions] etcd's ranges and how grants cover them (no database), then the table
//! itself against `SIGNON_TEST_DB` (skipped with a note without one).
use super::*;

fn p(key: &str, end: &[u8], perm: i16) -> Permission {
    Permission { role: "r".into(), key: key.as_bytes().to_vec(), range_end: end.to_vec(), perm }
}

#[test]
fn a_key_alone_is_let_only_where_it_is_granted() {
    let perms = [p("a", b"", READ)];
    assert!(permits(&perms, b"a", b"", READ));
    assert!(!permits(&perms, b"a", b"", WRITE), "read only");
    assert!(!permits(&perms, b"a", b"", READWRITE), "both asked, one given");
    assert!(!permits(&perms, b"ab", b"", READ), "a longer key is another key");
    assert!(!permits(&perms, b"a", b"b", READ), "the range a..b holds more than a");
}

#[test]
fn a_prefix_grant_covers_its_keys_and_ranges() {
    // etcd's prefix /x/: [/x/, /x0)
    let perms = [p("/x/", b"/x0", READWRITE)];
    assert!(permits(&perms, b"/x/a", b"", WRITE));
    assert!(permits(&perms, b"/x/", b"/x0", READ), "the whole prefix");
    assert!(permits(&perms, b"/x/a", b"/x/b", READ));
    assert!(!permits(&perms, b"/x/", b"/y", READ), "past its end");
    assert!(!permits(&perms, b"/w", b"/x/a", READ), "before its start");
    assert!(!permits(&perms, b"/y", b"", READ));
}

#[test]
fn a_zero_byte_end_is_every_key_from_there_on() {
    let all = [p("\0", &[0], READ)];
    assert!(permits(&all, b"anything", b"", READ));
    assert!(permits(&all, b"\0", &[0], READ), "the whole key space");
    let from = [p("m", &[0], READ)];
    assert!(permits(&from, b"z", &[0], READ));
    assert!(!permits(&from, b"a", &[0], READ), "starts before the grant");
    assert!(!permits(&[p("a", b"m", READ)], b"a", &[0], READ), "a bounded grant never covers an unbounded range");
}

#[test]
fn adjacent_and_overlapping_grants_cover_together_and_a_gap_does_not() {
    let perms = [p("a", b"c", READ), p("c", b"e", READ)];
    assert!(permits(&perms, b"b", b"d", READ), "across both");
    assert!(permits(&perms, b"a", b"e", READ));
    let overlap = [p("c", b"f", READ), p("a", b"d", READ)];
    assert!(permits(&overlap, b"a", b"f", READ), "in any order");
    let gap = [p("a", b"c", READ), p("d", b"f", READ)];
    assert!(!permits(&gap, b"b", b"e", READ), "c..d is not granted");
    assert!(permits(&gap, b"d", b"e", READ));
    // a grant of the other kind does not close a gap
    let mixed = [p("a", b"c", READ), p("c", b"e", WRITE)];
    assert!(!permits(&mixed, b"a", b"e", READ));
    assert!(permits(&mixed, b"c", b"d", WRITE));
}

#[test]
fn an_empty_range_is_no_way_around_a_permission() {
    // range_end before the key: etcd reads nothing, and lets it nowhere [review 2026-11-21]
    assert!(!permits(&[], b"b", b"a", READ));
    assert!(!permits(&[p("x", b"", READ)], b"b", b"a", READ));
    assert!(!permits(&[p("b", b"", READ)], b"b", b"a", READ), "not even where the key is");
    assert!(!permits(&[p("\0", &[0], READWRITE)], b"b", b"b", READ), "an end at its start");
}

#[test]
fn no_grant_and_a_nonsense_want_let_nothing() {
    assert!(!permits(&[], b"a", b"", READ));
    let all = [p("\0", &[0], READWRITE)];
    assert!(!permits(&all, b"a", b"", 0), "asking for nothing is no permission");
    assert!(!permits(&all, b"a", b"", 4));
    // a grant whose range is empty grants nothing
    assert!(!permits(&[p("b", b"a", READ)], b"b", b"", READ));
}

// ---- the table -------------------------------------------------------------------

async fn pool() -> Option<PgPool> {
    crate::test_pool("permissions").await
}

#[tokio::test]
async fn grants_revokes_and_reads_through_roles() {
    let Some(pool) = pool().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (role, other) = (format!("perm-{tag}"), format!("perm-other-{tag}"));
    assert!(crate::api::add_role(&pool, &role).await.unwrap());
    assert!(crate::api::add_role(&pool, &other).await.unwrap());
    assert!(!grant(&pool, &format!("none-{tag}"), "etcd", b"/a/", b"/a0", READ).await.unwrap(), "no such role");
    assert!(grant(&pool, &role, "etcd", b"/a/", b"/a0", READ).await.unwrap());
    assert!(grant(&pool, &role, "etcd", b"/a/", b"/a0", READWRITE).await.unwrap(), "the same range replaces");
    assert!(grant(&pool, &other, "etcd", b"/b", b"", WRITE).await.unwrap());
    assert!(grant(&pool, &role, "other", b"/z", b"", READ).await.unwrap(), "another key space");
    assert!(grant(&pool, &role, "etcd", b"/a/", b"/a0", 7).await.is_err(), "7 is no permission");
    let mine = of_role(&pool, &role, "etcd").await.unwrap();
    assert_eq!(mine, vec![Permission { role: role.clone(), key: b"/a/".to_vec(), range_end: b"/a0".to_vec(), perm: READWRITE }]);

    // an account with both roles has both roles' permissions, in the scope asked
    let user: Uuid = sqlx::query_scalar("INSERT INTO users (email, email_verified) VALUES ($1, true) RETURNING id")
        .bind(format!("perm-{tag}@test.example"))
        .fetch_one(&pool)
        .await
        .unwrap();
    crate::grant_role(&pool, user, &role).await.unwrap();
    crate::grant_role(&pool, user, &other).await.unwrap();
    let all = of_user(&pool, user, "etcd").await.unwrap();
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(permits(&all, b"/a/k", b"", WRITE));
    assert!(permits(&all, b"/b", b"", WRITE));
    assert!(!permits(&all, b"/z", b"", READ), "the other key space's grant is not etcd's");

    // revoking: the permission, then a role with its permissions
    assert!(revoke(&pool, &other, "etcd", b"/b", b"").await.unwrap());
    assert!(!revoke(&pool, &other, "etcd", b"/b", b"").await.unwrap(), "already gone");
    assert!(crate::api::delete_role(&pool, &role).await.unwrap());
    assert!(of_user(&pool, user, "etcd").await.unwrap().is_empty());
    assert!(of_role(&pool, &role, "other").await.unwrap().is_empty(), "the role's every scope went with it");
}


const FILE_TEXT: &str = r#"
[roles.reader]
permissions = [{ scope = "etcd", key = "/app/", range_end = "/app0", perm = 1 }, { scope = "other", key = "x", perm = 3 }]
[roles.all]
permissions = [{ scope = "etcd", key = "", range_end = "\u0000", perm = 3 }]
[users]
"00000000-0000-4000-8000-0000000000aa" = ["reader", "missing"]
"#;

/// [permissions] the file config read: roles' permissions by scope, accounts' roles; a
/// permission past 1-3 refused
#[test]
fn the_file_config_reads_and_refuses_a_bad_permission() {
    let c = parse_file(FILE_TEXT).unwrap();
    let p = file_permissions(&c, &["reader".to_string(), "missing".to_string()], "etcd");
    assert_eq!(p, vec![Permission { role: "reader".into(), key: b"/app/".to_vec(), range_end: b"/app0".to_vec(), perm: READ }]);
    assert!(permits(&p, b"/app/x", &[], READ) && !permits(&p, b"/app/x", &[], WRITE));
    let all = file_permissions(&c, &["all".to_string()], "etcd");
    assert!(permits(&all, b"anything", &[0], READWRITE), "the zero byte: every key on");
    assert!(parse_file("[roles.r]\npermissions = [{ scope = \"etcd\", key = \"a\", perm = 4 }]").is_err());
    assert!(parse_file("not toml [").is_err());
}

/// [permissions] the tables not there: the file serves the mappings, a grant or a revoke
/// is skipped; without a file the error stands
#[tokio::test]
async fn the_file_serves_when_the_tables_cannot() {
    let Some(pool) = crate::test_pool("perm-file").await else { return };
    let user = Uuid::parse_str("00000000-0000-4000-8000-0000000000aa").unwrap();
    // a database without the table: a schema of its own on the search path
    let schema = format!("pf_{}", Uuid::new_v4().simple());
    let url = std::env::var("SIGNON_TEST_DB").unwrap_or_else(|_| "postgres:///signon_test?host=/var/run/postgresql".to_string());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&pool).await.unwrap();
    let bare = sqlx::postgres::PgPoolOptions::new().max_connections(1)
        .after_connect({ let schema = schema.clone(); move |c, _| { let schema = schema.clone(); Box::pin(async move {
            sqlx::query(sqlx::AssertSqlSafe(format!("SET search_path = {schema}"))).execute(c).await.map(|_| ()) }) } })
        .connect(&url).await.unwrap();
    assert!(of_user(&bare, user, "etcd").await.is_err(), "no file: the error stands");
    set_file_config(parse_file(FILE_TEXT).unwrap());
    let p = of_user(&bare, user, "etcd").await.unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!(of_role(&bare, "all", "etcd").await.unwrap().len(), 1);
    assert!(!grant(&bare, "reader", "etcd", b"k", &[], READ).await.unwrap(), "skipped");
    assert!(!revoke(&bare, "reader", "etcd", b"k", &[]).await.unwrap(), "skipped");
    set_file_config(FileConfig::default());
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP SCHEMA {schema} CASCADE"))).execute(&pool).await.unwrap();
}
