//! Shared client-side verifier for ChirpAuth-issued ID tokens.
//!
//! ChirpAuth (the sibling crate / binary in this workspace) mints RS256 JWTs
//! and publishes its public keys via a JWKS endpoint at `{issuer}/jwks.json`.
//! Consumers (Drive, Exchange, Social Graph / personal-ecosystem, …) all need
//! the same verification routine: parse the JWT, fetch JWKS, verify the
//! signature, check `iss`/`aud`/`exp`, and return the verified subject.
//!
//! ChirpAuth issues two shapes of token under the same JWKS:
//!
//! - **Human** tokens come out of the Authorization Code + PKCE flow. They
//!   may carry `email` / `name` claims and have no `act` claim.
//! - **Machine** tokens come out of the `client_credentials` grant for
//!   confidential clients. They carry `act: "machine"` and `owner_sub`
//!   (the human chirp-sub responsible for the client) and never carry
//!   `email`. See `protocols/specs/machine-identity.md`.
//!
//! Callers opt in to machine acceptance with [`VerifyOptions::accept_machine`]
//! (default `false`). Services that only handle humans don't change behavior;
//! the returned [`ChirpVerifiedIdentity`] is an enum, so call sites `match` on
//! `Human { .. }` / `Machine { .. }`.
//!
//! [`verify_chirp_id_token`] returns a [`ChirpVerifiedToken`] carrying two
//! orthogonal axes: the [`Environment`] (`Production`/`Test`) the verifying
//! keyset belongs to — **provenance, derived from which issuer/JWKS matched,
//! not from any claim** — and the [`ChirpVerifiedIdentity`] principal
//! (`Human`/`Machine`). A relying party therefore cannot mistake a test
//! identity for a production one, or a machine for a human, by forgetting a
//! marker: both distinctions are in the type. Access the principal via
//! `token.identity`.
//!
//! ## Environment enforcement (0.7)
//!
//! The environment axis is now **enforced**, not merely reported. The verifier
//! derives the expected [`Environment`] from the configured issuer
//! ([`ChirpAuthConfig::environment`]) and rejects any token whose provenance
//! disagrees:
//!
//! - A **production**-configured relying party rejects a token carrying
//!   `test == true` with [`ChirpAuthError::EnvironmentMismatch`].
//! - A **test**-configured relying party (issuer `…/test/{tenant}`) rejects a
//!   token that does *not* carry `test == true`, also with
//!   [`ChirpAuthError::EnvironmentMismatch`].
//!
//! Test-acceptance is therefore derived from the issuer's environment, not from
//! a per-call flag. The old [`VerifyOptions::accept_test`] field is retained as
//! a deprecated no-op so 0.6 callers still compile; it no longer affects policy.

pub mod mint;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use std::collections::BTreeSet;
use time::OffsetDateTime;

/// The canonical production ChirpAuth issuer.
///
/// Consumers should derive their [`ChirpAuthConfig`] from this rather than
/// re-typing the URL; a typo in an issuer string is a silent
/// [`ChirpAuthError::ClaimMismatch`] at runtime.
pub const DEFAULT_ISSUER: &str = "https://signin.chirpauth.com";

/// Endpoint and audience to verify ChirpAuth tokens against.
///
/// Construct via [`ChirpAuthConfig::new`] (or [`ChirpAuthConfig::from_env`]).
/// The `jwks_uri` is **derived** (`{issuer}/jwks.json`) and cannot be set
/// independently of the issuer — this removes a whole class of misconfiguration
/// where a relying party verifies issuer A's claims against issuer B's keyset.
/// Tests that need to point the fetch at an in-process server use
/// [`ChirpAuthConfig::with_jwks_uri`].
#[derive(Clone, Debug)]
pub struct ChirpAuthConfig {
    issuer: String,
    jwks_uri: String,
    /// The set of audiences this relying party accepts. A token is accepted if
    /// *any* of its `aud` values is in this set. Always non-empty.
    accepted_audiences: BTreeSet<String>,
}

impl ChirpAuthConfig {
    /// Build a config for a single audience.
    ///
    /// The issuer is normalized (trimmed, trailing slash stripped) and the
    /// `jwks_uri` is derived as `{issuer}/jwks.json`.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self::with_audiences(issuer, std::iter::once(audience.into()))
    }

    /// Build a config that accepts any of several audiences (an allowlist).
    ///
    /// A token is accepted when *any* of its `aud` values is in `audiences`,
    /// checked in a single pass — callers no longer loop a verify-per-audience.
    /// An empty `audiences` iterator yields a config that accepts nothing
    /// (every token fails `aud` matching with [`ChirpAuthError::ClaimMismatch`]).
    pub fn with_audiences(
        issuer: impl Into<String>,
        audiences: impl IntoIterator<Item = String>,
    ) -> Self {
        let issuer = normalize_issuer(issuer.into());
        let jwks_uri = format!("{issuer}/jwks.json");
        Self {
            issuer,
            jwks_uri,
            accepted_audiences: audiences.into_iter().map(|a| a.trim().to_owned()).collect(),
        }
    }

    /// Override the JWKS fetch URL. **Test-only**: production callers must let
    /// the URL derive from the issuer. Returns `self` for chaining.
    pub fn with_jwks_uri(mut self, jwks_uri: impl Into<String>) -> Self {
        self.jwks_uri = jwks_uri.into();
        self
    }

    /// Add another accepted audience to the allowlist.
    pub fn add_audience(mut self, audience: impl Into<String>) -> Self {
        self.accepted_audiences.insert(audience.into().trim().to_owned());
        self
    }

    /// The normalized issuer this config verifies against.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The derived JWKS endpoint.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// The audience allowlist.
    pub fn accepted_audiences(&self) -> &BTreeSet<String> {
        &self.accepted_audiences
    }

    /// The [`Environment`] this config's issuer belongs to — the provenance
    /// the verifier enforces. A production issuer yields
    /// [`Environment::Production`]; a `…/test/{tenant}` issuer yields
    /// [`Environment::Test`].
    pub fn environment(&self) -> Environment {
        Environment::from_issuer(&self.issuer)
    }

    /// Build a config from `{prefix}_ISSUER` and `{prefix}_AUDIENCE` env vars.
    ///
    /// Pass an empty `prefix` for unprefixed `CHIRP_AUTH_ISSUER` /
    /// `CHIRP_AUTH_AUDIENCE`. Returns `None` if either variable is missing or
    /// empty — the caller is expected to treat that as "ChirpAuth not
    /// configured" rather than an error.
    pub fn from_env(prefix: &str) -> Option<Self> {
        let (issuer_var, audience_var) = env_var_names(prefix);
        let issuer = std::env::var(&issuer_var)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())?;
        let audience = std::env::var(&audience_var)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())?;
        Some(Self::new(issuer, audience))
    }
}

fn normalize_issuer(issuer: String) -> String {
    issuer.trim().trim_end_matches('/').to_owned()
}

fn env_var_names(prefix: &str) -> (String, String) {
    if prefix.is_empty() {
        ("CHIRP_AUTH_ISSUER".to_owned(), "CHIRP_AUTH_AUDIENCE".to_owned())
    } else {
        (format!("{prefix}_ISSUER"), format!("{prefix}_AUDIENCE"))
    }
}

/// The verified identity extracted from a ChirpAuth ID token.
///
/// Dispatch is keyed by the `act` claim:
///
/// - `act` absent → [`ChirpVerifiedIdentity::Human`]. `email` / `name` come
///   through from token claims when present; emptiness normalised to `None`.
/// - `act == "machine"` → [`ChirpVerifiedIdentity::Machine`]. `owner_sub`
///   is the human chirp-sub responsible for the confidential client.
///   `client_id` is the token's `aud` claim (single-value).
///
/// `sub` is always non-empty, ≤ 128 chars, and free of control characters.
#[derive(Clone, Debug)]
pub enum ChirpVerifiedIdentity {
    Human {
        sub: String,
        email: Option<String>,
        name: Option<String>,
        /// The root identity behind `sub`. For single-persona users
        /// (the only case ChirpAuth issues today) equals `sub`. When
        /// persona issuance ships, distinct from `sub` for any persona
        /// that's not its own root.
        ///
        /// Relying parties doing anti-evasion moderation should key on
        /// `root_sub` rather than `sub` — a banned root carries its ban
        /// across all personas. Defaults to `sub` when the claim is
        /// absent (handles tokens minted before this field existed,
        /// and machine tokens are never reached on this arm).
        root_sub: String,
    },
    Machine {
        sub: String,
        owner_sub: String,
        client_id: String,
    },
}

impl ChirpVerifiedIdentity {
    /// The token's `sub` claim regardless of variant.
    pub fn sub(&self) -> &str {
        match self {
            Self::Human { sub, .. } | Self::Machine { sub, .. } => sub,
        }
    }
}

/// Which ChirpAuth keyset verified this token — **provenance, not a claim**.
///
/// Derived from the issuer the token was verified against (and matched
/// exactly): a ChirpAuth test issuer is structurally `{prod_issuer}/test/{tenant}`
/// with its own per-tenant signing key and JWKS. A relying party configured with
/// only the production issuer therefore *cannot* observe [`Environment::Test`] —
/// it is unreachable by construction (a test token's `kid` is absent from the
/// prod JWKS and its `iss` won't match). Carry this into trust decisions so a
/// test identity can never be mistaken for a production one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Environment {
    Production,
    Test,
}

impl Environment {
    /// Classify a verified issuer. A test issuer ends in a single non-empty
    /// `/test/{tenant}` segment; everything else is production.
    pub fn from_issuer(issuer: &str) -> Self {
        match issuer.trim_end_matches('/').rsplit_once("/test/") {
            Some((_, tenant)) if !tenant.is_empty() && !tenant.contains('/') => Environment::Test,
            _ => Environment::Production,
        }
    }
}

/// A verified token: its [`Environment`] (provenance — which keyset verified it)
/// alongside the [`ChirpVerifiedIdentity`] (the `Human`/`Machine` principal).
///
/// Both axes are surfaced in the type so a relying party cannot honor a test
/// identity as production, or a machine where it expects a human, by forgetting
/// to inspect a marker — the distinction is structural, not a runtime check the
/// caller might skip.
#[derive(Clone, Debug)]
pub struct ChirpVerifiedToken {
    pub environment: Environment,
    pub identity: ChirpVerifiedIdentity,
}

/// Per-call knobs for [`verify_chirp_id_token`].
///
/// Defaults to human-only acceptance — machine tokens are rejected with
/// [`ChirpAuthError::MachineNotAllowed`] unless `accept_machine` is set.
/// Services that want to participate in the machine-identity protocol opt in
/// here; everyone else stays human-only with no code change.
///
/// `#[non_exhaustive]`: construct via `VerifyOptions { .. ..Default::default() }`
/// so future option additions stay non-breaking.
#[derive(Default, Clone, Debug)]
#[non_exhaustive]
pub struct VerifyOptions {
    /// When `true`, a human token with a missing or empty `email` claim is
    /// rejected with [`ChirpAuthError::EmailRequired`]. No effect on machine
    /// tokens (which never carry `email`).
    pub require_email: bool,
    /// When `true`, accept machine tokens (`act == "machine"`) in addition to
    /// human tokens. Default `false`.
    pub accept_machine: bool,
    /// Deprecated no-op, retained so 0.6 callers compile. Test-acceptance is
    /// now derived from the configured issuer's [`Environment`]
    /// ([`ChirpAuthConfig::environment`]), not from this flag. A
    /// production-configured RP always rejects `test == true` tokens; a
    /// test-configured RP always accepts them.
    #[deprecated(
        since = "0.7.0",
        note = "no-op: test acceptance is derived from the configured issuer's Environment"
    )]
    pub accept_test: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ChirpAuthError {
    #[error("malformed jwt")]
    MalformedToken,
    #[error("unsupported alg")]
    UnsupportedAlgorithm,
    #[error("jwks fetch failed: {0}")]
    JwksFetch(String),
    #[error("no matching key")]
    NoMatchingKey,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("issuer/audience claim mismatch")]
    ClaimMismatch,
    #[error("token expired")]
    Expired,
    #[error("invalid subject")]
    InvalidSubject,
    #[error("email claim required but missing")]
    EmailRequired,
    #[error("machine token not accepted by this endpoint")]
    MachineNotAllowed,
    #[error("machine token missing owner_sub")]
    MalformedMachineToken,
    /// The token's provenance (production vs. test) disagrees with the
    /// configured issuer's [`Environment`]. A production RP got a `test` token,
    /// or a test RP got a non-`test` token.
    #[error("token environment does not match configured issuer")]
    EnvironmentMismatch,
    /// No `Authorization: Bearer …` header, or an empty/whitespace token.
    #[error("missing or empty bearer token")]
    MissingBearer,
    /// Retained for backward compatibility (0.6). The 0.7 environment-mismatch
    /// path returns [`ChirpAuthError::EnvironmentMismatch`] instead.
    #[deprecated(since = "0.7.0", note = "replaced by EnvironmentMismatch")]
    #[error("test token not accepted by this endpoint")]
    TestTokenRejected,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
struct ChirpClaims {
    iss: String,
    sub: String,
    aud: AudienceClaim,
    exp: i64,
    #[serde(default)]
    act: Option<String>,
    #[serde(default)]
    owner_sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    root_sub: Option<String>,
    #[serde(default)]
    test: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    /// True iff at least one audience value is in the allowlist.
    fn matches_any(&self, allowed: &BTreeSet<String>) -> bool {
        match self {
            Self::One(audience) => allowed.contains(audience),
            Self::Many(audiences) => audiences.iter().any(|a| allowed.contains(a)),
        }
    }

    fn single(&self) -> Option<&str> {
        match self {
            Self::One(audience) => Some(audience.as_str()),
            Self::Many(audiences) if audiences.len() == 1 => Some(audiences[0].as_str()),
            Self::Many(_) => None,
        }
    }
}

/// A parsed JWKS document — the set of RSA signing keys ChirpAuth publishes.
/// Returned by [`fetch_jwks`] for callers that need direct key access.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// A single JWK (RSA public key) from a [`Jwks`] document.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: Option<String>,
    pub n: String,
    pub e: String,
}

struct JwtParts<'a> {
    header: &'a str,
    claims: &'a str,
    signature: &'a str,
    signing_input: &'a str,
}

fn jwt_parts(token: &str) -> Result<JwtParts<'_>, ChirpAuthError> {
    let mut segments = token.split('.');
    let header = segments.next().ok_or(ChirpAuthError::MalformedToken)?;
    let claims = segments.next().ok_or(ChirpAuthError::MalformedToken)?;
    let signature = segments.next().ok_or(ChirpAuthError::MalformedToken)?;
    if segments.next().is_some()
        || header.is_empty()
        || claims.is_empty()
        || signature.is_empty()
    {
        return Err(ChirpAuthError::MalformedToken);
    }
    let signing_input_len = header.len() + 1 + claims.len();
    Ok(JwtParts {
        header,
        claims,
        signature,
        signing_input: &token[..signing_input_len],
    })
}

fn verify_rsa_signature(
    key: &Jwk,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), ChirpAuthError> {
    let n = URL_SAFE_NO_PAD
        .decode(&key.n)
        .map_err(|_| ChirpAuthError::SignatureInvalid)?;
    let e = URL_SAFE_NO_PAD
        .decode(&key.e)
        .map_err(|_| ChirpAuthError::SignatureInvalid)?;
    RsaPublicKeyComponents { n: &n, e: &e }
        .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input, signature)
        .map_err(|_| ChirpAuthError::SignatureInvalid)
}

/// Extract a bearer token from an `Authorization` header.
///
/// Returns the token with the `Bearer ` prefix stripped and surrounding
/// whitespace trimmed, or `None` if the header is absent, not a `Bearer`
/// scheme, or the token is empty after trimming. The scheme match is
/// ASCII-case-insensitive per RFC 7235.
pub fn bearer_token(headers: &http::HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let rest = value.strip_prefix("Bearer ").or_else(|| {
        // Case-insensitive scheme match without allocating: split on the first
        // space and compare the scheme.
        let (scheme, rest) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("bearer").then_some(rest)
    })?;
    let token = rest.trim();
    (!token.is_empty()).then_some(token)
}

/// Fetch and parse the JWKS document at `config.jwks_uri`.
///
/// Exposed so key-binding-certificate verification (and any other downstream
/// RS256 use) can reuse one fetch+parse path instead of re-implementing it.
pub async fn fetch_jwks(
    client: &reqwest::Client,
    config: &ChirpAuthConfig,
) -> Result<Jwks, ChirpAuthError> {
    client
        .get(&config.jwks_uri)
        .send()
        .await
        .map_err(|error| ChirpAuthError::JwksFetch(error.to_string()))?
        .error_for_status()
        .map_err(|error| ChirpAuthError::JwksFetch(error.to_string()))?
        .json::<Jwks>()
        .await
        .map_err(|error| ChirpAuthError::JwksFetch(error.to_string()))
}

/// A verified RS256 JWS payload — the decoded claims after signature, `iss`,
/// `exp`, and (optionally) `aud` checks pass. Returned by
/// [`verify_rs256_jws`].
#[derive(Clone, Debug)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: i64,
    /// The raw JSON object of all claims, for callers that need claims beyond
    /// the standard set (e.g. a key-binding cert's embedded public key).
    pub raw: serde_json::Map<String, serde_json::Value>,
}

/// Verify an RS256 JWS against `config`'s JWKS and standard claims.
///
/// This is the low-level verifier [`verify_chirp_id_token`] is built on, exposed
/// so downstream verification of *other* ChirpAuth-signed artifacts (notably
/// key-binding certificates) reuses one audited RS256 path rather than
/// re-implementing JWKS fetch + signature checks.
///
/// Checks: RS256 alg pin (header and JWK), kid lookup in the JWKS, signature,
/// exact `iss == config.issuer`, and `exp` in the future. When `validate_aud`
/// is `true`, also requires at least one `aud` value in
/// [`ChirpAuthConfig::accepted_audiences`]. Does **not** apply machine/test
/// policy — that lives in [`verify_chirp_id_token`].
pub async fn verify_rs256_jws(
    client: &reqwest::Client,
    config: &ChirpAuthConfig,
    token: &str,
    validate_aud: bool,
) -> Result<Claims, ChirpAuthError> {
    let parts = jwt_parts(token)?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts.header)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts.claims)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts.signature)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    if header.alg != "RS256" {
        return Err(ChirpAuthError::UnsupportedAlgorithm);
    }

    let jwks = fetch_jwks(client, config).await?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == header.kid && key.kty == "RSA")
        .ok_or(ChirpAuthError::NoMatchingKey)?;
    if key.alg.as_deref().is_some_and(|alg| alg != "RS256") {
        return Err(ChirpAuthError::UnsupportedAlgorithm);
    }
    verify_rsa_signature(key, parts.signing_input.as_bytes(), &signature)?;

    let raw: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&claims_bytes).map_err(|_| ChirpAuthError::MalformedToken)?;
    let claims: ChirpClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| ChirpAuthError::MalformedToken)?;

    if claims.iss != config.issuer {
        return Err(ChirpAuthError::ClaimMismatch);
    }
    if validate_aud && !claims.aud.matches_any(&config.accepted_audiences) {
        return Err(ChirpAuthError::ClaimMismatch);
    }
    if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
        return Err(ChirpAuthError::Expired);
    }

    let aud = match &claims.aud {
        AudienceClaim::One(a) => vec![a.clone()],
        AudienceClaim::Many(many) => many.clone(),
    };
    Ok(Claims {
        iss: claims.iss,
        sub: claims.sub,
        aud,
        exp: claims.exp,
        raw,
    })
}

/// Extract the bearer token from `headers` and verify it in one call.
///
/// Convenience over [`bearer_token`] + [`verify_chirp_id_token`] so relying
/// parties stop hand-rolling that two-step in middleware. Returns the
/// [`ChirpVerifiedIdentity`] directly; callers needing the [`Environment`]
/// should use the lower-level pair. [`ChirpAuthError::MissingBearer`] when no
/// usable bearer token is present.
pub async fn verify_from_headers(
    client: &reqwest::Client,
    headers: &http::HeaderMap,
    config: &ChirpAuthConfig,
    options: VerifyOptions,
) -> Result<ChirpVerifiedIdentity, ChirpAuthError> {
    let token = bearer_token(headers).ok_or(ChirpAuthError::MissingBearer)?;
    verify_chirp_id_token(client, config, token, options)
        .await
        .map(|verified| verified.identity)
}

/// Verify a ChirpAuth-issued RS256 ID token end-to-end.
///
/// Fetches `config.jwks_uri` each call — callers that want caching should layer
/// it on top (ChirpAuth JWKS rotation is on the order of hours/days; per-request
/// fetch is fine for current call volumes but worth revisiting if hot).
///
/// Returns [`ChirpVerifiedIdentity::Human`] or [`ChirpVerifiedIdentity::Machine`]
/// based on the `act` claim. Callers that don't accept machine identities leave
/// `options.accept_machine = false` (the default) and never see a `Machine`
/// arm in practice — the verifier rejects with [`ChirpAuthError::MachineNotAllowed`]
/// first.
///
/// **Environment is enforced** (0.7): the expected [`Environment`] is derived
/// from `config`'s issuer, and a token whose provenance disagrees is rejected
/// with [`ChirpAuthError::EnvironmentMismatch`]. A production RP rejects a
/// `test == true` token; a test RP rejects a non-test token. This replaces the
/// per-call `accept_test` flag (now a deprecated no-op).
///
/// Errors are mapped granularly so the caller can decide which to surface as
/// "401 Unauthorized" vs "500 Internal" — most consumers collapse everything
/// to 401, which is correct.
pub async fn verify_chirp_id_token(
    client: &reqwest::Client,
    config: &ChirpAuthConfig,
    token: &str,
    options: VerifyOptions,
) -> Result<ChirpVerifiedToken, ChirpAuthError> {
    let parts = jwt_parts(token)?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts.header)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(parts.claims)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    let signature = URL_SAFE_NO_PAD
        .decode(parts.signature)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    if header.alg != "RS256" {
        return Err(ChirpAuthError::UnsupportedAlgorithm);
    }

    let jwks = fetch_jwks(client, config).await?;
    let key = jwks
        .keys
        .iter()
        .find(|key| key.kid == header.kid && key.kty == "RSA")
        .ok_or(ChirpAuthError::NoMatchingKey)?;
    if key.alg.as_deref().is_some_and(|alg| alg != "RS256") {
        return Err(ChirpAuthError::UnsupportedAlgorithm);
    }
    verify_rsa_signature(key, parts.signing_input.as_bytes(), &signature)?;

    let claims: ChirpClaims = serde_json::from_slice(&claims_bytes)
        .map_err(|_| ChirpAuthError::MalformedToken)?;
    if claims.iss != config.issuer || !claims.aud.matches_any(&config.accepted_audiences) {
        return Err(ChirpAuthError::ClaimMismatch);
    }
    if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
        return Err(ChirpAuthError::Expired);
    }

    // Provenance enforcement: the environment is fixed by the configured issuer
    // (hence which keyset verified this token — `claims.iss` was just confirmed
    // to equal `config.issuer`). The token's own `test` claim must agree:
    //   - Production issuer  ⇒ token must NOT be `test: true`.
    //   - Test issuer        ⇒ token MUST be `test: true`.
    // Either disagreement fails closed. This makes the environment axis a
    // hard boundary rather than a per-call opt-in a caller might forget.
    let environment = config.environment();
    let token_is_test = claims.test == Some(true);
    let token_environment = if token_is_test {
        Environment::Test
    } else {
        Environment::Production
    };
    if token_environment != environment {
        return Err(ChirpAuthError::EnvironmentMismatch);
    }

    let sub = claims.sub.trim().to_owned();
    if sub.is_empty() || sub.chars().count() > 128 || sub.chars().any(char::is_control) {
        return Err(ChirpAuthError::InvalidSubject);
    }

    let is_machine = matches!(claims.act.as_deref(), Some("machine"));
    if is_machine {
        if !options.accept_machine {
            return Err(ChirpAuthError::MachineNotAllowed);
        }
        let owner_sub = claims
            .owner_sub
            .as_ref()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or(ChirpAuthError::MalformedMachineToken)?;
        // Machine tokens MUST address a single client (the one that minted them).
        let client_id = claims
            .aud
            .single()
            .map(str::to_owned)
            .ok_or(ChirpAuthError::MalformedMachineToken)?;
        return Ok(ChirpVerifiedToken {
            environment,
            identity: ChirpVerifiedIdentity::Machine {
                sub,
                owner_sub,
                client_id,
            },
        });
    }

    let email = claims
        .email
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let name = claims
        .name
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    if options.require_email && email.is_none() {
        return Err(ChirpAuthError::EmailRequired);
    }
    // Backward-compat default: tokens minted before the `root_sub` claim
    // existed have a single-persona identity by construction, so the
    // root identity is the sub itself.
    let root_sub = claims
        .root_sub
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sub.clone());
    Ok(ChirpVerifiedToken {
        environment,
        identity: ChirpVerifiedIdentity::Human { sub, email, name, root_sub },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_with_prefix_reads_prefixed_vars() {
        // Use a unique prefix to avoid clobbering anything else.
        let prefix = "CHIRP_AUTH_CLIENT_TEST_PREFIX_A";
        // SAFETY: tests in this module are single-threaded by default per binary.
        unsafe {
            std::env::set_var(format!("{prefix}_ISSUER"), "https://example.test/");
            std::env::set_var(format!("{prefix}_AUDIENCE"), "drive");
        }
        let config = ChirpAuthConfig::from_env(prefix).expect("config");
        assert_eq!(config.issuer(), "https://example.test");
        assert!(config.accepted_audiences().contains("drive"));
        assert_eq!(config.jwks_uri(), "https://example.test/jwks.json");
        unsafe {
            std::env::remove_var(format!("{prefix}_ISSUER"));
            std::env::remove_var(format!("{prefix}_AUDIENCE"));
        }
    }

    #[test]
    fn from_env_returns_none_when_missing() {
        let prefix = "CHIRP_AUTH_CLIENT_TEST_PREFIX_MISSING";
        // ensure unset
        unsafe {
            std::env::remove_var(format!("{prefix}_ISSUER"));
            std::env::remove_var(format!("{prefix}_AUDIENCE"));
        }
        assert!(ChirpAuthConfig::from_env(prefix).is_none());
    }

    #[test]
    fn from_env_returns_none_when_empty() {
        let prefix = "CHIRP_AUTH_CLIENT_TEST_PREFIX_EMPTY";
        unsafe {
            std::env::set_var(format!("{prefix}_ISSUER"), "   ");
            std::env::set_var(format!("{prefix}_AUDIENCE"), "drive");
        }
        assert!(ChirpAuthConfig::from_env(prefix).is_none());
        unsafe {
            std::env::remove_var(format!("{prefix}_ISSUER"));
            std::env::remove_var(format!("{prefix}_AUDIENCE"));
        }
    }

    #[test]
    fn new_derives_jwks_uri_and_normalizes_issuer() {
        let config = ChirpAuthConfig::new("https://signin.chirpauth.com/", "drive");
        assert_eq!(config.issuer(), "https://signin.chirpauth.com");
        assert_eq!(config.jwks_uri(), "https://signin.chirpauth.com/jwks.json");
        assert_eq!(config.environment(), Environment::Production);
    }

    #[test]
    fn default_issuer_is_production_environment() {
        let config = ChirpAuthConfig::new(DEFAULT_ISSUER, "drive");
        assert_eq!(config.environment(), Environment::Production);
        assert_eq!(config.issuer(), "https://signin.chirpauth.com");
    }

    #[test]
    fn with_audiences_builds_allowlist() {
        let config = ChirpAuthConfig::with_audiences(
            DEFAULT_ISSUER,
            ["a".to_owned(), "b".to_owned(), "c".to_owned()],
        );
        assert!(config.accepted_audiences().contains("a"));
        assert!(config.accepted_audiences().contains("b"));
        assert!(config.accepted_audiences().contains("c"));
        assert!(!config.accepted_audiences().contains("d"));
    }

    #[test]
    fn add_audience_extends_allowlist() {
        let config = ChirpAuthConfig::new(DEFAULT_ISSUER, "a").add_audience("b");
        assert!(config.accepted_audiences().contains("a"));
        assert!(config.accepted_audiences().contains("b"));
    }

    #[tokio::test]
    async fn rejects_malformed_token() {
        let config = ChirpAuthConfig::new("https://example.test", "drive")
            .with_jwks_uri("https://example.test/jwks.json");
        let client = reqwest::Client::new();
        let err = verify_chirp_id_token(&client, &config, "not.a.jwt.too.many", VerifyOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ChirpAuthError::MalformedToken));
    }

    #[tokio::test]
    async fn rejects_two_segment_token() {
        let config = ChirpAuthConfig::new("https://example.test", "drive")
            .with_jwks_uri("https://example.test/jwks.json");
        let client = reqwest::Client::new();
        let err = verify_chirp_id_token(&client, &config, "abc.def", VerifyOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ChirpAuthError::MalformedToken));
    }

    #[test]
    fn chirp_claims_parses_root_sub_when_present_and_absent() {
        // Absent → None on the wire claim, which the verifier defaults to
        // `sub` (single-persona limit case + backward-compat with
        // pre-root_sub tokens).
        let absent: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"sub_a","aud":"x","exp":1}"#,
        )
        .expect("parse");
        assert_eq!(absent.root_sub, None);

        // Present and equal to sub → today's single-persona shape.
        let same: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"sub_a","aud":"x","exp":1,"root_sub":"sub_a"}"#,
        )
        .expect("parse");
        assert_eq!(same.root_sub.as_deref(), Some("sub_a"));

        // Present and distinct → forward-compat with persona issuance.
        let distinct: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"persona_xyz","aud":"x","exp":1,"root_sub":"sub_root_a"}"#,
        )
        .expect("parse");
        assert_eq!(distinct.root_sub.as_deref(), Some("sub_root_a"));
    }

    #[test]
    fn chirp_claims_parses_test_flag_when_present_and_absent() {
        // Absent → None, which the verifier treats as production provenance.
        let absent: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"sub_a","aud":"x","exp":1}"#,
        )
        .expect("parse");
        assert_eq!(absent.test, None);

        // Present and true → the value the verifier gates environment on.
        let present: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"sub_a","aud":"x","exp":1,"test":true}"#,
        )
        .expect("parse");
        assert_eq!(present.test, Some(true));
    }

    #[test]
    fn identity_sub_returns_underlying_sub() {
        let human = ChirpVerifiedIdentity::Human {
            sub: "sub_abc".into(),
            email: None,
            name: None,
            root_sub: "sub_abc".into(),
        };
        assert_eq!(human.sub(), "sub_abc");
        let machine = ChirpVerifiedIdentity::Machine {
            sub: "agent_xyz".into(),
            owner_sub: "sub_owner".into(),
            client_id: "cs_live_1".into(),
        };
        assert_eq!(machine.sub(), "agent_xyz");
    }

    // -------------------- bearer extraction --------------------

    fn headers_with_auth(value: &str) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        h.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    #[test]
    fn bearer_token_strips_prefix_and_trims() {
        let h = headers_with_auth("Bearer   abc.def.ghi  ");
        assert_eq!(bearer_token(&h), Some("abc.def.ghi"));
    }

    #[test]
    fn bearer_token_case_insensitive_scheme() {
        let h = headers_with_auth("bearer tok123");
        assert_eq!(bearer_token(&h), Some("tok123"));
        let h = headers_with_auth("BEARER tok456");
        assert_eq!(bearer_token(&h), Some("tok456"));
    }

    #[test]
    fn bearer_token_rejects_empty_after_prefix() {
        let h = headers_with_auth("Bearer    ");
        assert_eq!(bearer_token(&h), None);
        let h = headers_with_auth("Bearer ");
        assert_eq!(bearer_token(&h), None);
    }

    #[test]
    fn bearer_token_rejects_other_schemes() {
        let h = headers_with_auth("Basic dXNlcjpwYXNz");
        assert_eq!(bearer_token(&h), None);
        let h = headers_with_auth("Token abc");
        assert_eq!(bearer_token(&h), None);
    }

    #[test]
    fn bearer_token_none_when_header_absent() {
        let h = http::HeaderMap::new();
        assert_eq!(bearer_token(&h), None);
    }

    #[test]
    fn bearer_token_rejects_bare_scheme_word() {
        // "Bearer" with no space/value is not a valid bearer credential.
        let h = headers_with_auth("Bearer");
        assert_eq!(bearer_token(&h), None);
    }
}

// ---------------------------------------------------------------------------
// End-to-end verify-path tests.
//
// The tests above this module exercise env-var parsing and malformed-shortcut
// paths that fail before any JWKS fetch or signature check. The tests below
// stand up an in-process JWKS server, mint real RS256 tokens against a
// generated keypair, and assert the verifier behaves correctly on the full
// path: signature, kid lookup, algorithm pin, issuer/audience claim, expiry,
// machine-token gating, environment enforcement, and a handful of adversarial
// constructions (alg=none, alg-confusion via RS512, kid not in JWKS,
// issuer-suffix attack).
//
// One RSA-2048 keypair is generated lazily and shared across tests via
// `OnceLock` — RSA keygen is the slow part (~200ms); reusing the key keeps
// the suite cheap.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod verify_path_tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::traits::PublicKeyParts;
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use sha2::Sha256;
    use std::sync::OnceLock;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const KID: &str = "test-kid-1";
    const ISS: &str = "https://signin.test.example";
    const AUD: &str = "cs_test_audience";

    fn keypair() -> &'static RsaPrivateKey {
        static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = rand::thread_rng();
            RsaPrivateKey::new(&mut rng, 2048).expect("generate test RSA key")
        })
    }

    fn jwks_body_with_test_key() -> String {
        let pubkey = RsaPublicKey::from(keypair());
        let n = URL_SAFE_NO_PAD.encode(pubkey.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(pubkey.e().to_bytes_be());
        format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"{KID}","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#
        )
    }

    /// Bind 127.0.0.1:0 and serve `body` (as application/json) to every
    /// request that arrives until the test completes. Returns the
    /// `http://host:port/jwks.json` URL. The server task is detached — it
    /// dies when the test runtime tears down.
    async fn start_jwks_server(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/jwks.json");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(p) => p,
                    Err(_) => return,
                };
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        url
    }

    fn sign_with_test_key(signing_input: &[u8]) -> Vec<u8> {
        let signer = SigningKey::<Sha256>::new(keypair().clone());
        let mut rng = rand::thread_rng();
        signer.sign_with_rng(&mut rng, signing_input).to_bytes().to_vec()
    }

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s.as_bytes())
    }

    /// Build a JWT from header JSON + claims JSON, signing with our test key.
    fn make_signed_jwt(header_json: &str, claims_json: &str) -> String {
        let signing_input = format!("{}.{}", b64(header_json), b64(claims_json));
        let sig = sign_with_test_key(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    /// Like `make_signed_jwt` but lets the caller substitute the signature
    /// segment — for tampered-signature and alg-confusion tests.
    fn make_jwt_with_signature(header_json: &str, claims_json: &str, raw_sig: &[u8]) -> String {
        format!(
            "{}.{}.{}",
            b64(header_json),
            b64(claims_json),
            URL_SAFE_NO_PAD.encode(raw_sig)
        )
    }

    fn now_unix() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    fn good_claims(iss: &str, aud: &str, exp: i64) -> String {
        format!(
            r#"{{"iss":"{iss}","sub":"sub_test","aud":"{aud}","exp":{exp},"email":"u@example.test"}}"#
        )
    }

    fn good_header() -> String {
        format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#)
    }

    /// A production-issuer config whose JWKS fetch is pointed at the in-process
    /// server. The issuer (`ISS`) has no `/test/{tenant}` suffix, so its
    /// `environment()` is `Production`.
    fn config_pointing_at(jwks_uri: String) -> ChirpAuthConfig {
        ChirpAuthConfig::new(ISS, AUD).with_jwks_uri(jwks_uri)
    }

    // -------------------- happy path --------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn accepts_a_well_formed_signed_token_as_human() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        let identity = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("verify");
        assert_eq!(identity.environment, Environment::Production);
        match identity.identity {
            ChirpVerifiedIdentity::Human { sub, email, .. } => {
                assert_eq!(sub, "sub_test");
                assert_eq!(email.as_deref(), Some("u@example.test"));
            }
            _ => panic!("expected Human"),
        }
    }

    // -------------------- adversarial paths --------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_token_with_tampered_signature() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        // Corrupt the FIRST char of the signature segment. The first base64
        // char maps to a full leading byte, so flipping it always changes the
        // signature bytes (→ SignatureInvalid) while staying canonical base64.
        // Flipping the LAST char instead can land on non-canonical trailing
        // bits, which the decoder rejects as MalformedToken — and since the
        // signature varies per run (claims carry a live exp), that made the
        // expected-error assertion flaky.
        let (head, sig) = token.rsplit_once('.').expect("jwt has signature segment");
        let mut sig_chars: Vec<char> = sig.chars().collect();
        sig_chars[0] = if sig_chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = format!("{head}.{}", sig_chars.into_iter().collect::<String>());
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &tampered,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::SignatureInvalid), "got {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_expired_token() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() - 1));
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::Expired), "got {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_wrong_audience() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(
            &good_header(),
            &good_claims(ISS, "cs_test_someone_else", now_unix() + 3600),
        );
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::ClaimMismatch), "got {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_wrong_issuer() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(
            &good_header(),
            &good_claims("https://attacker.test", AUD, now_unix() + 3600),
        );
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::ClaimMismatch), "got {err:?}");
    }

    /// Classic issuer-suffix trick: a token whose `iss` ends with the
    /// expected issuer string but is actually a different domain. Exact
    /// equality (not `ends_with`) must reject.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_issuer_suffix_attack() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        // Note: not `https://signin.test.example.attacker.test` (suffix
        // append) because the expected ISS doesn't have a trailing slash; the
        // attack the test demonstrates is the symmetric "iss prepended" form
        // that a naive `.contains(expected)` check would let through.
        let attacker_iss = format!("https://attacker.test/path/{ISS}");
        let token = make_signed_jwt(
            &good_header(),
            &good_claims(&attacker_iss, AUD, now_unix() + 3600),
        );
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::ClaimMismatch), "got {err:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_alg_none_token() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        // alg=none with empty signature is the classic "none" attack.
        // Our verifier rejects this at jwt_parts (empty signature segment)
        // OR at the alg pin if non-empty. Either rejection is acceptable;
        // assert one of the two well-defined errors.
        let header = format!(r#"{{"alg":"none","typ":"JWT","kid":"{KID}"}}"#);
        let claims = good_claims(ISS, AUD, now_unix() + 3600);
        let token = format!("{}.{}.", b64(&header), b64(&claims));
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, ChirpAuthError::MalformedToken | ChirpAuthError::UnsupportedAlgorithm),
            "got {err:?}",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_explicit_other_algorithm() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let header = format!(r#"{{"alg":"RS512","typ":"JWT","kid":"{KID}"}}"#);
        let claims = good_claims(ISS, AUD, now_unix() + 3600);
        // Any garbage in the signature slot — verifier rejects on alg pin
        // before touching it.
        let token = make_jwt_with_signature(&header, &claims, &[0u8; 32]);
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::UnsupportedAlgorithm), "got {err:?}");
    }

    /// Algorithm-confusion / kid-confusion: token claims an RS256 alg with
    /// a kid the JWKS doesn't advertise. Must fail at key lookup, not
    /// silently accept against some other key.
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_unknown_kid() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let header = r#"{"alg":"RS256","typ":"JWT","kid":"never-issued"}"#;
        let claims = good_claims(ISS, AUD, now_unix() + 3600);
        let token = make_jwt_with_signature(header, &claims, &[0u8; 256]);
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::NoMatchingKey), "got {err:?}");
    }

    /// Machine tokens are rejected by default. Every Drive/Pigeon/Social-
    /// Graph code path that uses the default `VerifyOptions` relies on this.
    /// Confirm the verifier does not silently downgrade a machine token to
    /// a Human identity (and that the rejection happens AFTER signature
    /// validation, so the test mints a real signed machine token).
    #[tokio::test(flavor = "multi_thread")]
    async fn rejects_machine_token_when_accept_machine_false() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let exp = now_unix() + 3600;
        let claims = format!(
            r#"{{"iss":"{ISS}","sub":"agent_test","aud":"{AUD}","exp":{exp},"act":"machine","owner_sub":"sub_owner"}}"#
        );
        let token = make_signed_jwt(&good_header(), &claims);
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::MachineNotAllowed), "got {err:?}");
    }

    // -------------------- audience allowlist --------------------

    /// A config carrying several accepted audiences must accept a token whose
    /// single `aud` is any one of them — in one pass, no per-audience loop.
    #[tokio::test(flavor = "multi_thread")]
    async fn allowlist_accepts_any_listed_audience() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let config = ChirpAuthConfig::with_audiences(
            ISS,
            ["cs_one".to_owned(), AUD.to_owned(), "cs_three".to_owned()],
        )
        .with_jwks_uri(jwks);
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        let verified = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config,
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("verify");
        assert!(matches!(verified.identity, ChirpVerifiedIdentity::Human { .. }));
    }

    /// A token whose `aud` is NOT in the allowlist is rejected.
    #[tokio::test(flavor = "multi_thread")]
    async fn allowlist_rejects_unlisted_audience() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let config = ChirpAuthConfig::with_audiences(
            ISS,
            ["cs_one".to_owned(), "cs_two".to_owned()],
        )
        .with_jwks_uri(jwks);
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config,
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::ClaimMismatch), "got {err:?}");
    }

    /// A multi-valued `aud` array is accepted when any one value is allowed.
    #[tokio::test(flavor = "multi_thread")]
    async fn allowlist_accepts_multivalued_aud_intersection() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let config = ChirpAuthConfig::new(ISS, AUD).with_jwks_uri(jwks);
        let exp = now_unix() + 3600;
        let claims = format!(
            r#"{{"iss":"{ISS}","sub":"sub_test","aud":["cs_other","{AUD}"],"exp":{exp},"email":"u@example.test"}}"#
        );
        let token = make_signed_jwt(&good_header(), &claims);
        let verified = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config,
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("verify");
        assert!(matches!(verified.identity, ChirpVerifiedIdentity::Human { .. }));
    }

    // -------------------- verify_from_headers --------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_from_headers_extracts_and_verifies() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        let identity = verify_from_headers(
            &reqwest::Client::new(),
            &headers,
            &config_pointing_at(jwks),
            VerifyOptions::default(),
        )
        .await
        .expect("verify");
        assert!(matches!(identity, ChirpVerifiedIdentity::Human { .. }));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_from_headers_missing_bearer() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let headers = http::HeaderMap::new();
        let err = verify_from_headers(
            &reqwest::Client::new(),
            &headers,
            &config_pointing_at(jwks),
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::MissingBearer), "got {err:?}");
    }

    // -------------------- verify_rs256_jws (low-level) --------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rs256_jws_returns_claims_and_raw() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let config = config_pointing_at(jwks);
        let exp = now_unix() + 3600;
        // A key-binding-cert-shaped payload: standard claims plus an extra
        // field the high-level verifier doesn't model.
        let claims = format!(
            r#"{{"iss":"{ISS}","sub":"sub_test","aud":"{AUD}","exp":{exp},"bound_pubkey":"ed25519:abc"}}"#
        );
        let token = make_signed_jwt(&good_header(), &claims);
        let verified = verify_rs256_jws(&reqwest::Client::new(), &config, &token, true)
            .await
            .expect("verify");
        assert_eq!(verified.sub, "sub_test");
        assert_eq!(verified.aud, vec![AUD.to_owned()]);
        assert_eq!(
            verified.raw.get("bound_pubkey").and_then(|v| v.as_str()),
            Some("ed25519:abc")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_rs256_jws_skips_aud_when_not_validating() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let config = config_pointing_at(jwks);
        let exp = now_unix() + 3600;
        // aud not in allowlist — accepted because validate_aud = false.
        let claims = format!(
            r#"{{"iss":"{ISS}","sub":"sub_test","aud":"cs_unrelated","exp":{exp}}}"#
        );
        let token = make_signed_jwt(&good_header(), &claims);
        let verified = verify_rs256_jws(&reqwest::Client::new(), &config, &token, false)
            .await
            .expect("verify without aud validation");
        assert_eq!(verified.sub, "sub_test");
    }

    /// Machine tokens are rejected by default. (kept as a paired inverse below)
    #[tokio::test(flavor = "multi_thread")]
    async fn accepts_machine_token_when_accept_machine_true() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let exp = now_unix() + 3600;
        let claims = format!(
            r#"{{"iss":"{ISS}","sub":"agent_test","aud":"{AUD}","exp":{exp},"act":"machine","owner_sub":"sub_owner"}}"#
        );
        let token = make_signed_jwt(&good_header(), &claims);
        let identity = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions { require_email: false, accept_machine: true, ..Default::default() },
        )
        .await
        .expect("verify machine");
        assert_eq!(identity.environment, Environment::Production);
        match identity.identity {
            ChirpVerifiedIdentity::Machine { sub, owner_sub, client_id } => {
                assert_eq!(sub, "agent_test");
                assert_eq!(owner_sub, "sub_owner");
                assert_eq!(client_id, AUD);
            }
            _ => panic!("expected Machine"),
        }
    }

    // -------------------- consumer-profile contract tests --------------
    //
    // Three downstream services consume this crate and each calls
    // verify_chirp_id_token with a different VerifyOptions config:
    //
    //   Drive        → { accept_machine: true,  require_email: false }
    //   Pigeon       → { accept_machine: true,  require_email: false }
    //   Social Graph → { accept_machine: false, require_email: true  }

    fn drive_profile() -> VerifyOptions {
        VerifyOptions { accept_machine: true, require_email: false, ..Default::default() }
    }
    fn pigeon_profile() -> VerifyOptions {
        VerifyOptions { accept_machine: true, require_email: false, ..Default::default() }
    }
    fn social_graph_profile() -> VerifyOptions {
        VerifyOptions { accept_machine: false, require_email: true, ..Default::default() }
    }

    fn human_claims_with_email(iss: &str, aud: &str, exp: i64) -> String {
        format!(
            r#"{{"iss":"{iss}","sub":"sub_user","aud":"{aud}","exp":{exp},"email":"u@example.test"}}"#
        )
    }
    fn human_claims_without_email(iss: &str, aud: &str, exp: i64) -> String {
        format!(
            r#"{{"iss":"{iss}","sub":"sub_user","aud":"{aud}","exp":{exp}}}"#
        )
    }
    fn machine_claims(iss: &str, aud: &str, exp: i64) -> String {
        format!(
            r#"{{"iss":"{iss}","sub":"agent_x","aud":"{aud}","exp":{exp},"act":"machine","owner_sub":"sub_owner"}}"#
        )
    }

    async fn run(profile: VerifyOptions, claims: &str) -> Result<ChirpVerifiedIdentity, ChirpAuthError> {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), claims);
        verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            profile,
        )
        .await
        .map(|verified| verified.identity)
    }

    // -- Drive profile -------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn drive_profile_accepts_human_with_email() {
        let claims = human_claims_with_email(ISS, AUD, now_unix() + 3600);
        let id = run(drive_profile(), &claims).await.expect("accept");
        assert!(matches!(id, ChirpVerifiedIdentity::Human { .. }));
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn drive_profile_accepts_human_without_email() {
        let claims = human_claims_without_email(ISS, AUD, now_unix() + 3600);
        let id = run(drive_profile(), &claims).await.expect("accept");
        assert!(matches!(id, ChirpVerifiedIdentity::Human { email: None, .. }));
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn drive_profile_accepts_machine_token() {
        let claims = machine_claims(ISS, AUD, now_unix() + 3600);
        let id = run(drive_profile(), &claims).await.expect("accept");
        assert!(matches!(id, ChirpVerifiedIdentity::Machine { .. }));
    }

    // -- Pigeon profile (currently identical to Drive's) ---------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn pigeon_profile_matches_drive_profile() {
        assert_eq!(
            (drive_profile().accept_machine, drive_profile().require_email),
            (pigeon_profile().accept_machine, pigeon_profile().require_email),
            "Drive and Pigeon profiles diverged. Update this test if intentional.",
        );
    }

    // -- Social Graph profile ------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn social_graph_profile_accepts_human_with_email() {
        let claims = human_claims_with_email(ISS, AUD, now_unix() + 3600);
        let id = run(social_graph_profile(), &claims).await.expect("accept");
        assert!(matches!(id, ChirpVerifiedIdentity::Human { email: Some(_), .. }));
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn social_graph_profile_rejects_human_without_email() {
        let claims = human_claims_without_email(ISS, AUD, now_unix() + 3600);
        let err = run(social_graph_profile(), &claims).await.unwrap_err();
        assert!(matches!(err, ChirpAuthError::EmailRequired), "got {err:?}");
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn social_graph_profile_rejects_machine_token() {
        let claims = machine_claims(ISS, AUD, now_unix() + 3600);
        let err = run(social_graph_profile(), &claims).await.unwrap_err();
        assert!(matches!(err, ChirpAuthError::MachineNotAllowed), "got {err:?}");
    }

    // -------------------- environment enforcement --------------------
    //
    // The environment axis is now enforced. A production-configured RP must
    // reject a `test: true` token; a test-configured RP must reject a
    // non-test token. Both fail with EnvironmentMismatch.

    fn human_test_claims(iss: &str, aud: &str, exp: i64) -> String {
        format!(
            r#"{{"iss":"{iss}","sub":"sub_test","aud":"{aud}","exp":{exp},"email":"u@example.test","test":true}}"#
        )
    }

    /// A test issuer config (`…/test/{tenant}`). The JWKS is the same
    /// in-process server (in production the test keyset is disjoint, but for
    /// the verify-path test what matters is the issuer string the config and
    /// token agree on).
    fn test_issuer_config(jwks_uri: String) -> (ChirpAuthConfig, String) {
        let test_iss = format!("{ISS}/test/acme");
        let config = ChirpAuthConfig::new(&test_iss, AUD).with_jwks_uri(jwks_uri);
        (config, test_iss)
    }

    /// Production RP + production (non-test) token → accepted.
    #[tokio::test(flavor = "multi_thread")]
    async fn prod_rp_accepts_prod_token() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        let verified = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("verify");
        assert_eq!(verified.environment, Environment::Production);
    }

    /// Production RP + test token → rejected with EnvironmentMismatch. This is
    /// the core enforcement: a production relying party can never honor a token
    /// minted by a test deployment, even with a valid signature/iss/aud/exp.
    #[tokio::test(flavor = "multi_thread")]
    async fn prod_rp_rejects_test_token() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &human_test_claims(ISS, AUD, now_unix() + 3600));
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::EnvironmentMismatch), "got {err:?}");
    }

    /// Test RP + test token → accepted, and reported as Environment::Test.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_rp_accepts_test_token() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let (config, test_iss) = test_issuer_config(jwks);
        let token =
            make_signed_jwt(&good_header(), &human_test_claims(&test_iss, AUD, now_unix() + 3600));
        let verified = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config,
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("verify test token under test RP");
        assert_eq!(verified.environment, Environment::Test);
        assert!(matches!(verified.identity, ChirpVerifiedIdentity::Human { .. }));
    }

    /// Test RP + non-test token → rejected. The symmetric direction: a test
    /// deployment must not honor a production-shaped token.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_rp_rejects_non_test_token() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let (config, test_iss) = test_issuer_config(jwks);
        // Non-test claims (no `test: true`) but with the test issuer.
        let token = make_signed_jwt(&good_header(), &good_claims(&test_iss, AUD, now_unix() + 3600));
        let err = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config,
            &token,
            VerifyOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ChirpAuthError::EnvironmentMismatch), "got {err:?}");
    }

    /// A non-test token must still be accepted under the default options by a
    /// production RP — the environment gate only fires on disagreement.
    #[tokio::test(flavor = "multi_thread")]
    async fn accepts_non_test_token_by_default() {
        let jwks = start_jwks_server(jwks_body_with_test_key()).await;
        let token = make_signed_jwt(&good_header(), &good_claims(ISS, AUD, now_unix() + 3600));
        let identity = verify_chirp_id_token(
            &reqwest::Client::new(),
            &config_pointing_at(jwks),
            &token,
            VerifyOptions::default(),
        )
        .await
        .expect("verify non-test token");
        assert!(matches!(identity.identity, ChirpVerifiedIdentity::Human { .. }));
    }

    #[test]
    fn environment_from_issuer_classifies_provenance() {
        use Environment::{Production, Test};
        assert_eq!(Environment::from_issuer("https://signin.chirpauth.com"), Production);
        assert_eq!(Environment::from_issuer("https://signin.chirpauth.com/"), Production);
        assert_eq!(Environment::from_issuer("https://signin.chirpauth.com/test/acme"), Test);
        assert_eq!(Environment::from_issuer("https://signin.chirpauth.com/test/acme/"), Test);
        // multi-segment after /test/ is not a valid single-tenant test issuer
        assert_eq!(Environment::from_issuer("https://signin.chirpauth.com/test/a/b"), Production);
        // empty tenant, and a host merely named "test", are production
        assert_eq!(Environment::from_issuer("https://signin.chirpauth.com/test/"), Production);
        assert_eq!(Environment::from_issuer("https://test.example.com"), Production);
    }

    // -------------------- environment enforcement, quantified --------------
    //
    // Property P1 — environment/keyset soundness on the verifier side. The four
    // hand-written direction tests above spot-check the prod/test × prod/test
    // matrix with one issuer each. This quantifies the same enforcement over an
    // arbitrary tenant id AND both axes at once: with signature, iss, aud, and
    // exp all valid in every case (so the environment axis is isolated), the
    // verifier accepts IFF the issuer-derived environment matches the token's
    // `test` provenance. A test token can never be honored by a production RP,
    // and vice-versa, no matter how the tenant is spelled.
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

        #[test]
        fn env_enforced_accept_iff_environments_match(
            tenant in "[a-z0-9]{1,16}",
            use_test_issuer in any::<bool>(),
            token_is_test in any::<bool>(),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                let jwks = start_jwks_server(jwks_body_with_test_key()).await;
                let issuer = if use_test_issuer {
                    format!("{ISS}/test/{tenant}")
                } else {
                    ISS.to_string()
                };
                let config = ChirpAuthConfig::new(&issuer, AUD).with_jwks_uri(jwks);
                let expected_env = if use_test_issuer {
                    Environment::Test
                } else {
                    Environment::Production
                };
                let token_env = if token_is_test {
                    Environment::Test
                } else {
                    Environment::Production
                };

                let test_field = if token_is_test { r#","test":true"# } else { "" };
                let claims = format!(
                    r#"{{"iss":"{issuer}","sub":"sub_p","aud":"{AUD}","exp":{}{test_field}}}"#,
                    now_unix() + 3600,
                );
                let token = make_signed_jwt(&good_header(), &claims);
                let result = verify_chirp_id_token(
                    &reqwest::Client::new(),
                    &config,
                    &token,
                    VerifyOptions::default(),
                )
                .await;

                let should_accept = expected_env == token_env;
                prop_assert_eq!(
                    result.is_ok(),
                    should_accept,
                    "issuer={} token_is_test={}",
                    issuer,
                    token_is_test
                );
                if let Ok(verified) = result {
                    prop_assert_eq!(verified.environment, expected_env);
                }
                Ok(())
            })?;
        }
    }
}
