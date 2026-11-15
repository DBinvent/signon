# Contributing to signon

Thank you for helping. signon is MIT licensed; a contribution is accepted under the
same license.

## Issues

Open an issue on GitHub for a bug or a feature request. For a bug, give the signon
version (Cargo.toml) and the features it is built with, the PostgreSQL version, the
request the site got and what it answered (status and body, without secrets or
tokens), and the smallest steps that show it.

A security problem is not reported in a public issue: mail **support@dbinvent.com**.

## Pull requests

1. Fork the repository and branch from `main`.
2. Keep a change to one subject; describe what it changes and why.
3. Build and test it (below); add tests for what you change.
4. A message a user reads - an API error, a sentence of a mail - is a key in every
   `locales/*.yml`; an error's starts with a new `SO-Ennn` code. A change to the tables
   goes in `schema.yaml`. A new handler keeps the security
   invariants of [DESIGN.md](DESIGN.md) section 4.
5. Open the pull request against `main`.

## Build and test

```
cargo build --all-features
cargo test                  # the logic, and the sign-in flows when a test database answers
cargo test --all-features   # with SAML, the SSO broker and the test signers too
```

The sign-in flow tests (`src/flow_tests.rs`) need a scratch PostgreSQL database:
`SIGNON_TEST_DB`, by default `postgres:///signon_test` over the local socket.
Without one they print a note and pass. See the README's Tests section.

The tests that sign need `openssl` on the path: no private key and no SAML test document
is in the repository, so the first run makes them, under `tests/fixtures/`, and `.gitignore`
keeps them out. Never add a file that is named private or holds a private key.

Before a pull request, run the checks as well:

```
cargo audit      # known vulnerabilities in the pinned dependencies
cargo geiger     # unsafe code in signon and its dependencies
```

## Code of conduct

Taking part in this project means following its
[Code of Conduct](CODE_OF_CONDUCT.md).
