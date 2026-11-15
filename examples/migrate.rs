//! Applies `schema.yaml` to a database, standalone.
//!
//! A service calls `signon::migrate` at startup; this is the
//! same call with nothing else attached, for provisioning a fresh database or
//! checking what a schema change would do without booting a service.
//!
//! ```sh
//! cargo run --example migrate -- 'postgres:///mysite?host=/var/run/postgresql&user=mysite'
//! ```
//!
//! On the URL shape: `sqlx` rejects marg`s default
//! `postgresql://$USER:$PGPASSWORD@/$USER?host=...` form with "empty host".
//! Three slashes and an explicit `user=` parameter is the spelling both
//! `sqlx` and `schema_guard_tokio` accept.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber_init();

    let Some(db_url) = std::env::args().nth(1) else {
        eprintln!("usage: migrate <db_url>");
        std::process::exit(2);
    };

    signon::migrate(&db_url).await?;
    println!("schema applied");
    Ok(())
}

fn tracing_subscriber_init() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
}
