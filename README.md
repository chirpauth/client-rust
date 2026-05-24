# chirp-auth-client

A Rust client for verifying ID tokens issued by [ChirpAuth](https://signin.chirpauth.com), a personal OIDC sign-in service.

## What it does

- Fetches the ChirpAuth JWKS on each verify call (caching is left to the caller).
- Verifies RS256-signed ID tokens against the published signing keys.
- Validates the standard OIDC claims (`iss`, `aud`, `exp`).
- Dispatches on the `act` claim to distinguish human-issued from machine-issued tokens.
- Optionally requires the `email` claim when relying parties need it for user identity.

## Usage

```rust
use chirp_auth_client::{
    ChirpAuthConfig, ChirpVerifiedIdentity, VerifyOptions, verify_chirp_id_token,
};

let config = ChirpAuthConfig {
    issuer: "https://signin.chirpauth.com".to_string(),
    audience: "cs_live_your_client_id".to_string(),
    jwks_uri: "https://signin.chirpauth.com/jwks.json".to_string(),
};
let http_client = reqwest::Client::new();
let identity = verify_chirp_id_token(
    &http_client,
    &config,
    presented_jwt,
    VerifyOptions { require_email: true, accept_machine: false },
)
.await?;

match identity {
    ChirpVerifiedIdentity::Human { sub, email, name } => { /* ... */ }
    ChirpVerifiedIdentity::Machine { sub, owner_sub, client_id } => { /* ... */ }
}
```

`ChirpAuthConfig::from_env(prefix)` is also available for the common case of
reading `{PREFIX}_ISSUER` / `{PREFIX}_AUDIENCE` from the environment (pass an
empty prefix for unprefixed `CHIRP_AUTH_*`).

## License

Dual-licensed under MIT or Apache-2.0, at your option.
