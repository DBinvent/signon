//! [api] Sign-in and the session check without a browser, against `SIGNON_TEST_DB`
//! (skipped with a note without one).
use super::*;
use crate::{Config, Mailer};

async fn state() -> Option<AccountState> {
    let pool = crate::test_pool("api").await?;
    AccountState::from_env_with_mailer(pool, Config::new("Api test", "https://api.test"), Mailer::disabled()).await.ok()
}

/// a verified account with a password, and its address
async fn make_account(state: &AccountState, tag: &str, verified: bool) -> (Uuid, String) {
    let email = format!("api-{tag}@test.example");
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (email, email_verified, password_hash) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(&email)
    .bind(verified)
    .bind(password::hash("correct horse battery").unwrap())
    .fetch_one(&state.pool)
    .await
    .unwrap();
    (id, email)
}

#[tokio::test]
async fn a_signed_in_token_names_its_account_and_roles_until_signed_out() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (id, email) = make_account(&state, &tag, true).await;
    let role = format!("api-role-{tag}");
    assert!(add_role(&state.pool, &role).await.unwrap());
    assert!(!add_role(&state.pool, &role).await.unwrap(), "there already");
    crate::grant_role(&state.pool, id, &role).await.unwrap();

    let s = sign_in(&state, &email.to_uppercase(), "correct horse battery", "10.0.0.1", "etcd").await.unwrap();
    assert_eq!(s.user_id, id);
    assert_eq!(s.expires_in, state.config.session_ttl);
    let who = identity(&state.pool, &s.token).await.unwrap().unwrap();
    assert_eq!(who, Identity { user_id: id, email: Some(email.clone()), roles: vec![role.clone()] });
    // the role taken: the next check says so, nothing cached here
    assert!(revoke_role(&state.pool, id, &role).await.unwrap());
    assert!(!revoke_role(&state.pool, id, &role).await.unwrap(), "already taken");
    assert!(identity(&state.pool, &s.token).await.unwrap().unwrap().roles.is_empty());
    // the session row says how it was made
    let via: Option<String> = sqlx::query_scalar("SELECT via FROM sessions WHERE user_id = $1").bind(id).fetch_one(&state.pool).await.unwrap();
    assert_eq!(via.as_deref(), Some("etcd"));

    assert!(sign_out(&state.pool, &s.token).await.unwrap());
    assert!(!sign_out(&state.pool, &s.token).await.unwrap(), "gone already");
    assert_eq!(identity(&state.pool, &s.token).await.unwrap(), None);
    assert!(delete_role(&state.pool, &role).await.unwrap());
    assert!(!delete_role(&state.pool, &role).await.unwrap());
}

#[tokio::test]
async fn a_wrong_password_an_unknown_address_and_an_unverified_account_are_one_answer() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (_, email) = make_account(&state, &tag, true).await;
    let (_, unverified) = make_account(&state, &format!("{tag}-u"), false).await;
    let nobody = format!("nobody-{tag}@test.example");
    for (who, pw) in [(email.as_str(), "wrong"), (nobody.as_str(), "correct horse battery"), (unverified.as_str(), "correct horse battery")] {
        let r = sign_in(&state, who, pw, "10.0.0.2", "etcd").await;
        assert!(matches!(r, Err(SignInRefusal::Credentials)), "{who}: {r:?}");
    }
}

#[tokio::test]
async fn a_suspended_account_and_an_expired_session_stop_resolving() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (id, email) = make_account(&state, &tag, true).await;
    let s = sign_in(&state, &email, "correct horse battery", "10.0.0.3", "etcd").await.unwrap();
    crate::set_user_suspended(&state.pool, id, true).await.unwrap();
    assert_eq!(identity(&state.pool, &s.token).await.unwrap(), None, "suspended since");
    assert!(matches!(sign_in(&state, &email, "correct horse battery", "10.0.0.3", "etcd").await, Err(SignInRefusal::Credentials)));
    crate::set_user_suspended(&state.pool, id, false).await.unwrap();
    assert!(identity(&state.pool, &s.token).await.unwrap().is_some(), "reinstated");
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second' WHERE user_id = $1").bind(id).execute(&state.pool).await.unwrap();
    assert_eq!(identity(&state.pool, &s.token).await.unwrap(), None, "expired");
}

#[tokio::test]
async fn the_check_writes_last_seen_at_once_a_minute_at_most() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (id, email) = make_account(&state, &tag, true).await;
    let s = sign_in(&state, &email, "correct horse battery", "10.0.0.4", "etcd").await.unwrap();
    let seen = || async {
        sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>("SELECT last_seen_at FROM sessions WHERE user_id = $1")
            .bind(id)
            .fetch_one(&state.pool)
            .await
            .unwrap()
    };
    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '30 seconds' WHERE user_id = $1").bind(id).execute(&state.pool).await.unwrap();
    let before = seen().await;
    identity(&state.pool, &s.token).await.unwrap().unwrap();
    assert_eq!(seen().await, before, "seen 30 s ago: not written again");
    sqlx::query("UPDATE sessions SET last_seen_at = now() - interval '2 minutes' WHERE user_id = $1").bind(id).execute(&state.pool).await.unwrap();
    let stale = seen().await;
    identity(&state.pool, &s.token).await.unwrap().unwrap();
    assert!(seen().await > stale, "seen 2 min ago: written");
}

#[tokio::test]
async fn sign_ins_share_login_s_limit_per_address() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (_, email) = make_account(&state, &tag, true).await;
    // LOGIN_PER_EMAIL wrong tries, from different clients: the next one is refused as too many
    for i in 0..crate::routes::LOGIN_PER_EMAIL {
        let r = sign_in(&state, &email, "wrong", &format!("10.1.0.{i}"), "etcd").await;
        assert!(matches!(r, Err(SignInRefusal::Credentials)), "{i}: {r:?}");
    }
    let r = sign_in(&state, &email, "correct horse battery", "10.1.1.1", "etcd").await;
    assert!(matches!(r, Err(SignInRefusal::TooMany)), "{r:?}");
}

#[tokio::test]
async fn accounts_and_roles_list_in_order() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let (id, email) = make_account(&state, &tag, true).await;
    let role = format!("api-list-{tag}");
    add_role(&state.pool, &role).await.unwrap();
    crate::grant_role(&state.pool, id, &role).await.unwrap();
    assert!(accounts(&state.pool).await.unwrap().contains(&email));
    let all = roles(&state.pool).await.unwrap();
    assert!(all.contains(&role));
    assert!(all.windows(2).all(|w| w[0] <= w[1]), "in order");
    assert_eq!(super::account(&state.pool, &email.to_uppercase()).await.unwrap().unwrap().roles, vec![role.clone()]);
    assert_eq!(super::account(&state.pool, &format!("none-{tag}@test.example")).await.unwrap(), None);
    delete_role(&state.pool, &role).await.unwrap();
}

#[tokio::test]
async fn an_added_account_signs_in_and_a_taken_address_is_said() {
    let Some(state) = state().await else { return };
    let tag = Uuid::new_v4().simple().to_string();
    let email = format!("Add-{tag}@Test.Example");
    let id = add_account(&state.pool, &email, "a long enough pass 123").await.unwrap().unwrap();
    assert_eq!(add_account(&state.pool, &email.to_lowercase(), "a long enough pass 123").await.unwrap(), None, "taken");
    assert!(add_account(&state.pool, &format!("short-{tag}@test.example"), "x").await.is_err(), "the policy holds");
    let s = sign_in(&state, &email, "a long enough pass 123", "10.2.0.1", "etcd").await.unwrap();
    assert_eq!(s.user_id, id);
}
