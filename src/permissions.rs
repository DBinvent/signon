//! [permissions] What a role may do on a range of keys (feature `permissions`):
//! an etcd server's permissions first, any key space after - `scope` names
//! it. A range is etcd's: an empty `range_end` is the key alone, a single zero byte is
//! every key from `key` on, anything else the end of the range, not included. Read per
//! request, as roles are, so a revoked permission stops working at once.
//!
//! [permissions] **A functional backup**: the tables stay in the
//! database, and signon depends on no etcd. With PostgreSQL not answering, or the tables not
//! there, a basic file config serves the mappings - each role's permissions, each account's
//! roles - ([`set_file`], `SIGNON_PERMISSIONS_FILE`); a grant or a revoke, the other table
//! operations, is skipped then (answered `false`, said in the log).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

/// [permissions] The file config: TOML -
///
/// ```toml
/// [roles.reader]
/// permissions = [{ scope = "etcd", key = "/app/", range_end = "/app0", perm = 1 }]
/// [users]
/// "4f0c...-uuid" = ["reader"]
/// ```
///
/// A key and a range end as text (`"\u0000"` the zero byte: every key from `key` on).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub roles: BTreeMap<String, FileRole>,
    /// each account, by its id, and its roles
    #[serde(default)]
    pub users: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct FileRole {
    #[serde(default)]
    pub permissions: Vec<FilePermission>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct FilePermission {
    pub scope: String,
    pub key: String,
    #[serde(default)]
    pub range_end: String,
    pub perm: i16,
}

static FILE: RwLock<Option<Arc<FileConfig>>> = RwLock::new(None);

/// [permissions] The file config read: from now on it serves the mappings whenever the
/// tables cannot. A permission that is not 1, 2 or 3 is refused.
pub fn set_file(path: &str) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow::anyhow!("permissions file {path}: {e}"))?;
    set_file_config(parse_file(&text)?);
    Ok(())
}

/// [permissions] The file config's text read
pub fn parse_file(text: &str) -> anyhow::Result<FileConfig> {
    let c: FileConfig = toml::from_str(text).map_err(|e| anyhow::anyhow!("permissions file: {e}"))?;
    for (role, r) in &c.roles {
        for p in &r.permissions {
            anyhow::ensure!(p.perm & READWRITE != 0 && p.perm & !READWRITE == 0,
                "permissions file: role {role}: a permission is 1 read, 2 write or 3 both, not {}", p.perm);
        }
    }
    Ok(c)
}

/// [permissions] The file config, or none again
pub fn set_file_config(c: FileConfig) {
    *FILE.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(c));
}

fn file() -> Option<Arc<FileConfig>> {
    let held = FILE.read().unwrap_or_else(|p| p.into_inner()).clone();
    if held.is_some() {
        return held;
    }
    // read once from the environment, when nothing set it
    let path = std::env::var("SIGNON_PERMISSIONS_FILE").ok().filter(|p| !p.trim().is_empty())?;
    match set_file(&path) {
        Ok(()) => FILE.read().unwrap_or_else(|p| p.into_inner()).clone(),
        Err(e) => {
            tracing::warn!(%e, "permissions file not read");
            None
        }
    }
}

/// [permissions] Whether a table operation failed for a reason the file serves: PostgreSQL
/// not answering, or the tables not there
fn unavailable(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Database(d) => matches!(d.code().as_deref(), Some("42P01") | Some("3D000") | Some("57P03")),
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed => true,
        _ => false,
    }
}

fn file_permissions(c: &FileConfig, roles: &[String], scope: &str) -> Vec<Permission> {
    let mut out: Vec<Permission> = roles.iter().filter_map(|r| c.roles.get(r).map(|fr| (r, fr)))
        .flat_map(|(r, fr)| fr.permissions.iter().filter(|p| p.scope == scope).map(move |p| Permission {
            role: r.clone(), key: p.key.as_bytes().to_vec(), range_end: p.range_end.as_bytes().to_vec(), perm: p.perm }))
        .collect();
    out.sort_by(|a, b| (&a.key, &a.range_end).cmp(&(&b.key, &b.range_end)));
    out
}

/// a table operation the file cannot serve, skipped: `false`, and said
fn skipped(what: &str, e: &sqlx::Error) -> anyhow::Result<bool> {
    tracing::warn!(%e, "{what} skipped: the permissions file is in use");
    Ok(false)
}

pub const READ: i16 = 1;
pub const WRITE: i16 = 2;
pub const READWRITE: i16 = 3;

/// One permission of a role
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Permission {
    pub role: String,
    pub key: Vec<u8>,
    pub range_end: Vec<u8>,
    /// [`READ`], [`WRITE`] or [`READWRITE`]
    pub perm: i16,
}

/// `[start, end)`, `end` `None` for no end: a range of etcd's as an interval of keys
fn interval(key: &[u8], range_end: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    if range_end.is_empty() {
        // the key alone: up to its immediate successor
        let mut next = key.to_vec();
        next.push(0);
        (key.to_vec(), Some(next))
    } else if range_end == [0] {
        (key.to_vec(), None)
    } else {
        (key.to_vec(), Some(range_end.to_vec()))
    }
}

/// Whether `perms` let `want` ([`READ`], [`WRITE`] or both) on the range `key`..
/// `range_end`: the range must lie inside what the permissions that give `want` cover
/// together - two adjacent grants cover a range across both, as etcd's do. A range
/// whose end is not after its start is let nowhere ([review 2026-11-21]: as etcd's
/// check finds no interval in it). `want` 0 or past [`READWRITE`] is let nowhere.
pub fn permits(perms: &[Permission], key: &[u8], range_end: &[u8], want: i16) -> bool {
    if want & READWRITE == 0 || want & !READWRITE != 0 {
        return false;
    }
    let (start, end) = interval(key, range_end);
    if matches!(&end, Some(e) if *e <= start) {
        return false;
    }
    let mut granted: Vec<(Vec<u8>, Option<Vec<u8>>)> = perms
        .iter()
        .filter(|p| p.perm & want == want)
        .map(|p| interval(&p.key, &p.range_end))
        .filter(|(s, e)| e.as_ref().is_none_or(|e| e > s))
        .collect();
    granted.sort_by(|a, b| a.0.cmp(&b.0));
    // the covered stretch is [start, to); each grant beginning at or before `to` may
    // stretch it, the first one beginning after it is a gap no later one can close
    let mut to = start;
    for (s, e) in granted {
        if s > to {
            return false;
        }
        match e {
            None => return true,
            Some(e) if e > to => to = e,
            Some(_) => {}
        }
        if matches!(&end, Some(want_to) if to >= *want_to) {
            return true;
        }
    }
    false
}

/// Gives `role` `perm` on the range, in key space `scope`; the same range again
/// replaces its permission, as etcd's grant does. `false`: no such role.
pub async fn grant(pool: &PgPool, role: &str, scope: &str, key: &[u8], range_end: &[u8], perm: i16) -> anyhow::Result<bool> {
    anyhow::ensure!(perm & READWRITE != 0 && perm & !READWRITE == 0, "a permission is 1 read, 2 write or 3 both, not {perm}");
    let done = sqlx::query(
        "INSERT INTO role_permissions (role_id, scope, key, range_end, perm) \
         SELECT id, $2, $3, $4, $5 FROM roles WHERE name = $1 \
         ON CONFLICT (role_id, scope, key, range_end) DO UPDATE SET perm = EXCLUDED.perm",
    )
    .bind(role)
    .bind(scope)
    .bind(key)
    .bind(range_end)
    .bind(perm)
    .execute(pool)
    .await;
    match done {
        Ok(r) => Ok(r.rows_affected() == 1),
        Err(e) if unavailable(&e) && file().is_some() => skipped("grant", &e),
        Err(e) => Err(e.into()),
    }
}

/// Takes the permission on exactly this range from `role`; `false`: it had none
pub async fn revoke(pool: &PgPool, role: &str, scope: &str, key: &[u8], range_end: &[u8]) -> anyhow::Result<bool> {
    let done = sqlx::query(
        "DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE name = $1) \
         AND scope = $2 AND key = $3 AND range_end = $4",
    )
    .bind(role)
    .bind(scope)
    .bind(key)
    .bind(range_end)
    .execute(pool)
    .await;
    match done {
        Ok(r) => Ok(r.rows_affected() > 0),
        Err(e) if unavailable(&e) && file().is_some() => skipped("revoke", &e),
        Err(e) => Err(e.into()),
    }
}

/// A role's permissions in `scope`, by key
pub async fn of_role(pool: &PgPool, role: &str, scope: &str) -> anyhow::Result<Vec<Permission>> {
    let got = sqlx::query_as::<_, Permission>(
        "SELECT r.name AS role, p.key, p.range_end, p.perm FROM role_permissions p \
         JOIN roles r ON r.id = p.role_id WHERE r.name = $1 AND p.scope = $2 ORDER BY p.key, p.range_end",
    )
    .bind(role)
    .bind(scope)
    .fetch_all(pool)
    .await;
    match got {
        Ok(v) => Ok(v),
        Err(e) if unavailable(&e) => match file() {
            Some(c) => Ok(file_permissions(&c, &[role.to_string()], scope)),
            None => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
}

/// Every permission an account has in `scope`, through all its roles
pub async fn of_user(pool: &PgPool, user_id: Uuid, scope: &str) -> anyhow::Result<Vec<Permission>> {
    let got = sqlx::query_as::<_, Permission>(
        "SELECT r.name AS role, p.key, p.range_end, p.perm FROM role_permissions p \
         JOIN roles r ON r.id = p.role_id JOIN user_roles ur ON ur.role_id = p.role_id \
         WHERE ur.user_id = $1 AND p.scope = $2 ORDER BY p.key, p.range_end",
    )
    .bind(user_id)
    .bind(scope)
    .fetch_all(pool)
    .await;
    match got {
        Ok(v) => Ok(v),
        Err(e) if unavailable(&e) => match file() {
            Some(c) => {
                let roles = c.users.get(&user_id.to_string()).cloned().unwrap_or_default();
                Ok(file_permissions(&c, &roles, scope))
            }
            None => Err(e.into()),
        },
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
#[path = "permissions_test.rs"]
mod tests;
