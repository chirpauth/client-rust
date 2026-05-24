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
//! (default `false`). Services that only handle humans don't change behavior
//! across the 0.1 → 0.2 upgrade; the breaking change is that the returned
//! [`ChirpVerifiedIdentity`] is now an enum, so call sites must `match` on
//! `Human { .. }` instead of accessing fields directly.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use time::OffsetDateTime;

/// Endpoint and audience to verify ChirpAuth tokens against.
///
/// `jwks_uri` defaults to `{issuer}/jwks.json` when constructed via
/// [`ChirpAuthConfig::from_env`]; callers can override by constructing the
/// struct directly (e.g. tests pointing at a mock server).
#[derive(Clone, Debug)]
pub struct ChirpAuthConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
}

impl ChirpAuthConfig {
    /// Build a config from `{prefix}_ISSUER` and `{prefix}_AUDIENCE` env vars.
    ///
    /// Pass an empty `prefix` for unprefixed `CHIRP_AUTH_ISSUER` / `CHIRP_AUTH_AUDIENCE`.
    /// Returns `None` if either variable is missing or empty — the caller is
    /// expected to treat that as "ChirpAuth not configured" rather than an error.
    pub fn from_env(prefix: &str) -> Option<Self> {
        let (issuer_var, audience_var) = env_var_names(prefix);
        let issuer = std::env::var(&issuer_var)
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_owned())
            .filter(|value| !value.is_empty())?;
        let audience = std::env::var(&audience_var)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())?;
        Some(Self {
            jwks_uri: format!("{issuer}/jwks.json"),
            issuer,
            audience,
        })
    }
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
        /// `true` when ChirpAuth's stored developer record for this `sub`
        /// has `is_operator = true`. Surfaced so relying parties can gate
        /// operator-only surfaces (e.g. social-graph's moderation
        /// endpoints) on a per-token basis. Defaults to `false` when the
        /// claim is absent — every non-operator token, including those
        /// minted before this field existed.
        is_operator: bool,
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

/// Per-call knobs for [`verify_chirp_id_token`].
///
/// Defaults to human-only acceptance — machine tokens are rejected with
/// [`ChirpAuthError::MachineNotAllowed`] unless `accept_machine` is set.
/// Services that want to participate in the machine-identity protocol opt in
/// here; everyone else stays human-only with no code change.
#[derive(Default, Clone, Debug)]
pub struct VerifyOptions {
    /// When `true`, a human token with a missing or empty `email` claim is
    /// rejected with [`ChirpAuthError::EmailRequired`]. No effect on machine
    /// tokens (which never carry `email`).
    pub require_email: bool,
    /// When `true`, accept machine tokens (`act == "machine"`) in addition to
    /// human tokens. Default `false`.
    pub accept_machine: bool,
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
    is_operator: Option<bool>,
    #[serde(default)]
    root_sub: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    One(String),
    Many(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(audience) => audience == expected,
            Self::Many(audiences) => audiences.iter().any(|audience| audience == expected),
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

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    alg: Option<String>,
    n: String,
    e: String,
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
/// Errors are mapped granularly so the caller can decide which to surface as
/// "401 Unauthorized" vs "500 Internal" — most consumers collapse everything
/// to 401, which is correct.
pub async fn verify_chirp_id_token(
    client: &reqwest::Client,
    config: &ChirpAuthConfig,
    token: &str,
    options: VerifyOptions,
) -> Result<ChirpVerifiedIdentity, ChirpAuthError> {
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

    let jwks = client
        .get(&config.jwks_uri)
        .send()
        .await
        .map_err(|error| ChirpAuthError::JwksFetch(error.to_string()))?
        .error_for_status()
        .map_err(|error| ChirpAuthError::JwksFetch(error.to_string()))?
        .json::<Jwks>()
        .await
        .map_err(|error| ChirpAuthError::JwksFetch(error.to_string()))?;
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
    if claims.iss != config.issuer || !claims.aud.contains(&config.audience) {
        return Err(ChirpAuthError::ClaimMismatch);
    }
    if claims.exp <= OffsetDateTime::now_utc().unix_timestamp() {
        return Err(ChirpAuthError::Expired);
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
        return Ok(ChirpVerifiedIdentity::Machine {
            sub,
            owner_sub,
            client_id,
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
    let is_operator = claims.is_operator.unwrap_or(false);
    // Backward-compat default: tokens minted before the `root_sub` claim
    // existed have a single-persona identity by construction, so the
    // root identity is the sub itself.
    let root_sub = claims
        .root_sub
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| sub.clone());
    Ok(ChirpVerifiedIdentity::Human { sub, email, name, is_operator, root_sub })
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
        assert_eq!(config.issuer, "https://example.test");
        assert_eq!(config.audience, "drive");
        assert_eq!(config.jwks_uri, "https://example.test/jwks.json");
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

    #[tokio::test]
    async fn rejects_malformed_token() {
        let config = ChirpAuthConfig {
            issuer: "https://example.test".into(),
            audience: "drive".into(),
            jwks_uri: "https://example.test/jwks.json".into(),
        };
        let client = reqwest::Client::new();
        let err = verify_chirp_id_token(&client, &config, "not.a.jwt.too.many", VerifyOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ChirpAuthError::MalformedToken));
    }

    #[tokio::test]
    async fn rejects_two_segment_token() {
        let config = ChirpAuthConfig {
            issuer: "https://example.test".into(),
            audience: "drive".into(),
            jwks_uri: "https://example.test/jwks.json".into(),
        };
        let client = reqwest::Client::new();
        let err = verify_chirp_id_token(&client, &config, "abc.def", VerifyOptions::default())
            .await
            .unwrap_err();
        assert!(matches!(err, ChirpAuthError::MalformedToken));
    }

    #[test]
    fn chirp_auth_client_verify_surfaces_is_operator() {
        // Deserialize the claim shape directly — exercising the absent-claim
        // and present-true paths without standing up a full JWKS / JWT
        // verification harness. The Default `false` for absent and the
        // surfaced `true` for present are both load-bearing.
        let absent: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"sub_a","aud":"x","exp":1}"#,
        )
        .expect("parse");
        assert_eq!(absent.is_operator, None);

        let present: ChirpClaims = serde_json::from_str(
            r#"{"iss":"x","sub":"sub_b","aud":"x","exp":1,"is_operator":true}"#,
        )
        .expect("parse");
        assert_eq!(present.is_operator, Some(true));

        // And the identity shape carries the bool through.
        let identity = ChirpVerifiedIdentity::Human {
            sub: "sub_b".into(),
            email: None,
            name: None,
            is_operator: true,
            root_sub: "sub_b".into(),
        };
        match identity {
            ChirpVerifiedIdentity::Human { is_operator, .. } => assert!(is_operator),
            _ => panic!("expected Human"),
        }
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
    fn identity_sub_returns_underlying_sub() {
        let human = ChirpVerifiedIdentity::Human {
            sub: "sub_abc".into(),
            email: None,
            name: None,
            is_operator: false,
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
}
