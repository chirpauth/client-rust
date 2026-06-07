# chirp-auth-client

A Rust client for verifying ID tokens issued by [ChirpAuth](https://signin.chirpauth.com), a personal OIDC sign-in service.

## What it does

- Fetches the ChirpAuth JWKS on each verify call (caching is left to the caller).
- Verifies RS256-signed ID tokens against the published signing keys.
- Validates the standard OIDC claims (`iss`, `aud`, `exp`).
- Dispatches on the `act` claim to distinguish human-issued from machine-issued tokens.
- Never exposes a user's email: a relying party cannot obtain it. ChirpAuth holds
  the address to send magic links / route mediated contact.

## Usage

```rust
use chirp_auth_client::{
    ChirpAuthConfig, ChirpVerifiedIdentity, DEFAULT_ISSUER, VerifyOptions,
    verify_from_headers,
};

// jwks_uri is derived as `{issuer}/jwks.json` — it cannot be hand-set wrong.
let config = ChirpAuthConfig::new(DEFAULT_ISSUER, "cs_live_your_client_id");
let http_client = reqwest::Client::new();

// Extract `Authorization: Bearer …` and verify in one call.
let identity = verify_from_headers(
    &http_client,
    request_headers,
    &config,
    VerifyOptions { accept_machine: true, ..Default::default() },
)
.await?;

match identity {
    ChirpVerifiedIdentity::Human { sub, name, root_sub } => { /* ... */ }
    ChirpVerifiedIdentity::Machine { sub, owner_sub, client_id } => { /* ... */ }
}
```

`ChirpAuthConfig::with_audiences(issuer, audiences)` builds an audience
allowlist (a token is accepted if any of its `aud` values is in the set, checked
in one pass). `ChirpAuthConfig::from_env(prefix)` reads
`{PREFIX}_ISSUER` / `{PREFIX}_AUDIENCE` from the environment (empty prefix for
unprefixed `CHIRP_AUTH_*`).

### Environment enforcement

The verifier derives the expected `Environment` (`Production`/`Test`) from the
configured issuer and **rejects** a token whose provenance disagrees: a
production-configured relying party rejects a test-issuer (`test: true`) token,
and a test-configured RP (issuer `…/test/{tenant}`) rejects a non-test token,
both with `ChirpAuthError::EnvironmentMismatch`. Test-acceptance is no longer a
per-call flag (`VerifyOptions::accept_test` is a deprecated no-op).

### Lower-level surface

- `bearer_token(&HeaderMap) -> Option<&str>` — strip/validate a bearer token.
- `fetch_jwks(...)` + `verify_rs256_jws(config, token, validate_aud)` — reuse the
  audited RS256 verifier for other ChirpAuth-signed artifacts (e.g. key-binding
  certificates) instead of re-implementing JWKS fetch and signature checks.

## Testing

```sh
cargo test
```

Tests cover the end-to-end verify path (signed-by-test-keypair tokens against
an in-process JWKS server): signature, kid lookup, algorithm pin, issuer/audience
claim, expiry, machine-token gating, environment enforcement (prod-RP-rejects-test
and test-RP-rejects-prod), the audience allowlist, bearer extraction, and
adversarial constructions — plus consumer-profile contract tests that pin the
`VerifyOptions` shapes Drive, Pigeon, and Social Graph each use. CI runs the
suite on every push and PR.

## License

Dual-licensed under MIT or Apache-2.0, at your option.
