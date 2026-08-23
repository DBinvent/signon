//! One-shot mail deliverability check.
//!
//! Builds the same `Mailer` the services use, from the same environment, and
//! sends one message. Point it at an address you control — a bounce from a
//! made-up address costs sender reputation.
//!
//! ```sh
//! # Cloudflare Email Sending
//! EMAIL_PROVIDER=cloudflare \
//! CF_ACCOUNT_ID=58a47fbc106121925e936c15c72b9d37 \
//! CF_EMAIL_TOKEN=<token with account Email Sending: Send> \
//! EMAIL_FROM=no-reply@knownby.work EMAIL_FROM_NAME=QW \
//!   cargo run --example send_test -- vlad4kr7@gmail.com
//!
//! # SMTP relay
//! EMAIL_HOST=smtp-relay.brevo.com EMAIL_PORT=587 \
//! EMAIL_LOGIN=... EMAIL_KEY=... EMAIL_FROM=no-reply@knownby.work \
//!   cargo run --example send_test -- vlad4kr7@gmail.com
//! ```
//!
//! It runs `is_healthy()` first and stops there if the probe fails, because
//! `send` never returns an error into its caller by design — a silent failure
//! is exactly what this example exists to make loud.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber_init();

    let Some(to) = std::env::args().nth(1) else {
        eprintln!("usage: send_test <recipient@example.com>");
        std::process::exit(2);
    };

    let mailer = user_mgmt::Mailer::from_env()?;

    if !mailer.is_healthy().await {
        anyhow::bail!(
            "mailer health probe failed — the credentials or the sender domain are wrong. \
             Nothing was sent. For Cloudflare, a token that can read email/sending/zones but \
             not send returns 10000 Authentication error on the send call, so check the \
             token has the account-level Email Sending send permission."
        );
    }
    println!("health probe: ok ({})", mailer.host());

    let unsubscribe = "https://dash.knownby.work/news/unsubscribe?token=send-test-not-a-real-token";
    mailer
        .send_with_headers(
            &to,
            "user_mgmt send test",
            format!(
                "This is a one-off deliverability test from user_mgmt.\n\n\
                 If it arrived, registration, password-reset and newsletter-confirmation mail \
                 will reach this address too.\n\n\
                 Unsubscribe (not a real token, this message is not from a list):\n{unsubscribe}\n"
            ),
            format!(
                "<p>This is a one-off deliverability test from <code>user_mgmt</code>.</p>\
                 <p>If it arrived, registration, password-reset and newsletter-confirmation mail \
                 will reach this address too.</p>\
                 <p><a href=\"{unsubscribe}\">Unsubscribe</a> (not a real token — this message is \
                 not from a list).</p>"
            ),
            &[
                ("List-Unsubscribe".to_string(), format!("<{unsubscribe}>")),
                (
                    "List-Unsubscribe-Post".to_string(),
                    "List-Unsubscribe=One-Click".to_string(),
                ),
            ],
        )
        .await;

    // `send` swallows its own errors on purpose (see its doc), so the only
    // honest thing to report here is that the attempt was made. The log line
    // it emits — "email sent", or the rejection — is the actual result.
    println!("send attempted to {to} — check the log line above, and the inbox");
    Ok(())
}

/// `Mailer::send` reports its outcome through `tracing` and never through a
/// return value, so without a subscriber this example would print "send
/// attempted" and hide the reason it failed.
fn tracing_subscriber_init() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
}
