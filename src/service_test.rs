//! [service] service accounts: made, three ways in, the token
use super::*;

fn account() -> ServiceAccount {
    ServiceAccount { id: Uuid::parse_str("00000000-0000-4000-8000-0000000000bb").unwrap(), name: "etl".into(),
        pg_role: "etl_rw".into(), groups: "[\"loaders\"]".into(), enabled: true }
}

/// [service] the client-credentials token carries the account, its role and groups
#[test]
fn a_token_carries_the_account_and_its_role() {
    let t = issue(b"k", &account(), Duration::from_secs(60)).unwrap();
    assert_eq!(verify(b"k", &t).unwrap(), account());
    assert!(verify(b"x", &t).is_err());
    assert_eq!(account().group_list(), vec!["loaders".to_string()]);
    let mut h = HeaderMap::new();
    use base64::Engine;
    h.insert(header::AUTHORIZATION, format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("etl:s3cr:et")).parse().unwrap());
    assert_eq!(basic(&h), Some(("etl".into(), "s3cr:et".into())));
}

#[cfg(feature = "labac")]
#[test]
fn labac_sees_a_service_account_by_its_groups() {
    let s = account().subject();
    assert!(s.groups.contains("loaders") && s.version == 1);
}

/// [service] in the database: made, switched off and on; a client secret, an API key and a
/// PostgreSQL password each let it in, the one before a rotation no more
#[tokio::test]
async fn three_ways_in_each_rotated() {
    let Some(pool) = crate::test_pool("service").await else { return };
    let name = format!("svc-{}", Uuid::new_v4().simple());
    assert!(create(&pool, "a:b", "r", &[]).await.is_err(), "no ':' in a client id");
    let a = create(&pool, &name, "app_ro", &["readers".to_string()]).await.unwrap();
    assert_eq!(by_name(&pool, &name).await.unwrap(), Some(a.clone()));
    let s1 = rotate_client_secret(&pool, a.id).await.unwrap();
    assert_eq!(by_client_credentials(&pool, &name, &s1).await.unwrap().map(|x| x.id), Some(a.id));
    let s2 = rotate_client_secret(&pool, a.id).await.unwrap();
    assert!(by_client_credentials(&pool, &name, &s1).await.unwrap().is_none(), "rotated");
    assert!(by_client_credentials(&pool, &name, &s2).await.unwrap().is_some());
    let k = rotate_api_key(&pool, a.id).await.unwrap();
    assert_eq!(by_api_key(&pool, &k).await.unwrap().map(|x| x.pg_role), Some("app_ro".to_string()));
    assert!(by_api_key(&pool, "nope").await.unwrap().is_none());
    assert!(set_pg_password(&pool, a.id, "short").await.is_err());
    set_pg_password(&pool, a.id, "a long enough password").await.unwrap();
    assert!(by_pg_password(&pool, &name, "a long enough password").await.unwrap().is_some());
    assert!(by_pg_password(&pool, &name, "wrong password!!").await.unwrap().is_none());
    assert!(by_pg_password(&pool, "nobody", "a long enough password").await.unwrap().is_none());
    assert!(all_enabled(&pool).await.unwrap().iter().any(|x| x.id == a.id));
    assert!(set_enabled(&pool, a.id, false).await.unwrap());
    assert!(!all_enabled(&pool).await.unwrap().iter().any(|x| x.id == a.id), "off: not listed");
    assert!(by_api_key(&pool, &k).await.unwrap().is_none(), "off: no way in");
    assert!(by_client_credentials(&pool, &name, &s2).await.unwrap().is_none());
    assert!(rotate_api_key(&pool, Uuid::new_v4()).await.is_err(), "no such account");
}


/// [review 2026-11-21] a token is current only while its account is on and not rotated since,
/// and says the role as it is now
#[tokio::test]
async fn a_token_stops_with_its_account() {
    let Some(pool) = crate::test_pool("service-current").await else { return };
    let a = create(&pool, &format!("svc-{}", Uuid::new_v4().simple()), "app_ro", &[]).await.unwrap();
    let t = issue(b"k", &a, Duration::from_secs(60)).unwrap();
    assert_eq!(current(&pool, b"k", &t).await.unwrap().map(|x| x.id), Some(a.id));
    assert!(current(&pool, b"other", &t).await.unwrap().is_none());
    sqlx::query("UPDATE service_accounts SET pg_role = 'app_rw' WHERE id = $1").bind(a.id).execute(&pool).await.unwrap();
    assert_eq!(current(&pool, b"k", &t).await.unwrap().map(|x| x.pg_role), Some("app_rw".to_string()), "the role now");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(set_enabled(&pool, a.id, false).await.unwrap());
    assert!(current(&pool, b"k", &t).await.unwrap().is_none(), "off");
    assert!(set_enabled(&pool, a.id, true).await.unwrap());
    assert!(current(&pool, b"k", &t).await.unwrap().is_none(), "issued before the switch");
    let fresh = issue(b"k", &a, Duration::from_secs(60)).unwrap();
    assert!(current(&pool, b"k", &fresh).await.unwrap().is_some());
}
