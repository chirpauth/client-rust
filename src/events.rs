//! Verifying ChirpAuth's signed app events (`chirp-event+jwt`).
//!
//! When someone deletes their Chirp account, ChirpAuth POSTs one signed
//! `user.deleted` event to every app they used that registered a deletion
//! webhook, naming them by the pairwise `sub` that app knows (chirp-auth
//! `docs/account-deletion.md`). The body is a compact RS256 JWS with
//! `typ: chirp-event+jwt`, signed under a key published only at
//! `{issuer}/events/jwks.json`, never in the ID-token JWKS. So no ID token can be
//! replayed as an event, and no event can authenticate a request.
//!
//! An event carries no `exp`, so [`verify_rs256_jws`](crate::verify_rs256_jws)
//! does not fit; freshness is bounded on `iat` instead. ChirpAuth re-signs every
//! delivery attempt with a fresh `iat` and a stable `event_id`, so the bound
//! never refuses a genuine retry.
//!
//! [`verify_chirp_event`] is the one verifier every receiver calls (chirp-auth#87:
//! Social Graph and Pigeon each hand-rolled one, with different rules). The
//! receiver keeps only its audience choice and its side effect.

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::jwks_cache::JwksCache;
use crate::{jwt_parts, verify_rsa_signature, ChirpAuthConfig, ChirpAuthError};

/// JWT `typ` of a ChirpAuth event token. Distinct from every token class a
/// ChirpAuth verifier accepts, so an event is never honored as anything else.
pub const EVENT_TYP: &str = "chirp-event+jwt";
/// The event `type` sent when an account is deleted.
pub const USER_DELETED: &str = "user.deleted";
/// An event signed longer ago than this is refused. ChirpAuth re-signs each
/// delivery attempt, so only a captured token replayed later hits this.
pub const MAX_EVENT_AGE_SECS: i64 = 10 * 60;
/// How far in the future an `iat` may be, for clock skew between ChirpAuth and
/// the receiver.
pub const MAX_EVENT_CLOCK_SKEW_SECS: i64 = 60;
/// The longest `sub` accepted. Chirp's pairwise subs are far shorter; anything
/// longer is not one.
pub const MAX_EVENT_SUB_LEN: usize = 128;

/// A verified ChirpAuth event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChirpEvent {
    /// The person this app knows as `sub` deleted their Chirp account at
    /// `deleted_at` (Unix seconds). Delivery is at-least-once with a stable
    /// `event_id`: make the side effect idempotent, or dedupe on `event_id`.
    UserDeleted {
        sub: String,
        event_id: String,
        deleted_at: i64,
    },
}

/// Why an event was refused.
///
/// A receiver typically answers `Unverified` with 401, `Invalid` with 400 (or
/// 401: ChirpAuth retries any non-2xx alike), and `KeysUnavailable` with 503.
/// The `&'static str` reasons are for logs; they never contain token content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EventRejection {
    /// Not provably a fresh event from this issuer to one of the accepted
    /// audiences: malformed, wrong `alg`/`typ`, unknown key, bad signature,
    /// wrong `iss` or `aud`, or `iat` outside the accepted window.
    #[error("event not verified: {0}")]
    Unverified(&'static str),
    /// Signed by ChirpAuth and addressed here, but not an event this verifier
    /// can return: an unsupported `type`, malformed claims, `jti != event_id`,
    /// or a malformed `sub`.
    #[error("event invalid: {0}")]
    Invalid(&'static str),
    /// The event key set could not be fetched. Says nothing about the token.
    #[error("event key set unavailable: {0}")]
    KeysUnavailable(String),
}

/// Where `config`'s issuer publishes its event-signing keys. Derived from the
/// issuer, like the ID-token JWKS, so it cannot be pointed at the wrong set.
pub fn events_jwks_uri(config: &ChirpAuthConfig) -> String {
    format!("{}/events/jwks.json", config.issuer())
}

/// Verify a ChirpAuth event token (the raw webhook body; surrounding whitespace
/// is ignored).
///
/// `accepted_audiences` is the set of this app's client ids the event may be
/// addressed to. It is separate from [`ChirpAuthConfig::accepted_audiences`]
/// because an event names a person by the pairwise sub of the app in its `aud`:
/// accept only the clients whose subs this receiver stores. An empty set accepts
/// nothing.
///
/// In order, before any network call: three-segment compact JWS, `alg = RS256`,
/// `typ = chirp-event+jwt`. So garbage never costs an outbound request. Then the
/// signature against [`events_jwks_uri`], through the same per-process JWKS cache
/// as the ID-token verifier: an unknown `kid` refetches the set (at most once per
/// 30 s), so a key ChirpAuth mints after this process's last fetch verifies on
/// the next delivery attempt at the latest (ChirpAuth's first retry is 60 s
/// later). Then the claims: `iss` equals the configured issuer; `aud` is in
/// `accepted_audiences` and equals `client_id`; `iat` within
/// [`MAX_EVENT_AGE_SECS`] in the past and [`MAX_EVENT_CLOCK_SKEW_SECS`] in the
/// future; a supported `type`; `jti == event_id`, non-empty; `sub` non-empty, at
/// most [`MAX_EVENT_SUB_LEN`] bytes, with no control characters.
pub async fn verify_chirp_event(
    client: &reqwest::Client,
    config: &ChirpAuthConfig,
    token: &str,
    accepted_audiences: &BTreeSet<String>,
) -> Result<ChirpEvent, EventRejection> {
    verify_with(
        crate::jwks_cache::global(),
        client,
        config,
        token,
        accepted_audiences,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
}

#[derive(Deserialize)]
struct EventHeader {
    alg: String,
    typ: String,
    kid: String,
}

/// The claims every ChirpAuth event carries, whatever its `type`.
#[derive(Deserialize)]
struct EnvelopeClaims {
    iss: String,
    aud: String,
    client_id: String,
    iat: i64,
    #[serde(rename = "type")]
    event_type: String,
}

#[derive(Deserialize)]
struct UserDeletedClaims {
    jti: String,
    event_id: String,
    sub: String,
    deleted_at: i64,
}

fn decode(segment: &str) -> Result<Vec<u8>, EventRejection> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| EventRejection::Unverified("bad base64url"))
}

pub(crate) async fn verify_with(
    cache: &JwksCache,
    client: &reqwest::Client,
    config: &ChirpAuthConfig,
    token: &str,
    accepted_audiences: &BTreeSet<String>,
    now: i64,
) -> Result<ChirpEvent, EventRejection> {
    use EventRejection::{Invalid, KeysUnavailable, Unverified};

    // Structure first: nothing below here is reached by garbage, and nothing
    // before the key lookup makes a network call.
    let parts = jwt_parts(token.trim()).map_err(|_| Unverified("not a compact JWS"))?;
    let header: EventHeader =
        serde_json::from_slice(&decode(parts.header)?).map_err(|_| Unverified("bad header"))?;
    if header.alg != "RS256" {
        return Err(Unverified("alg is not RS256"));
    }
    if header.typ != EVENT_TYP {
        return Err(Unverified("typ is not chirp-event+jwt"));
    }
    let signature = decode(parts.signature)?;
    let claims_bytes = decode(parts.claims)?;

    let key = cache
        .key(client, &events_jwks_uri(config), &header.kid)
        .await
        .map_err(|error| match error {
            ChirpAuthError::JwksFetch(reason) => KeysUnavailable(reason),
            _ => Unverified("no event key with this kid"),
        })?;
    if key.alg.as_deref().is_some_and(|alg| alg != "RS256") {
        return Err(Unverified("key is not RS256"));
    }
    verify_rsa_signature(&key, parts.signing_input.as_bytes(), &signature)
        .map_err(|_| Unverified("bad signature"))?;

    // Signed by ChirpAuth from here on.
    let envelope: EnvelopeClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| Invalid("bad claims"))?;
    if envelope.iss != config.issuer() {
        return Err(Unverified("wrong issuer"));
    }
    if !accepted_audiences.contains(&envelope.aud) || envelope.client_id != envelope.aud {
        return Err(Unverified("not addressed to an accepted audience"));
    }
    if envelope.iat < now - MAX_EVENT_AGE_SECS || envelope.iat > now + MAX_EVENT_CLOCK_SKEW_SECS {
        return Err(Unverified("iat outside the accepted window"));
    }
    match envelope.event_type.as_str() {
        USER_DELETED => {
            let claims: UserDeletedClaims =
                serde_json::from_slice(&claims_bytes).map_err(|_| Invalid("bad claims"))?;
            if claims.event_id.is_empty() || claims.jti != claims.event_id {
                return Err(Invalid("jti must equal a non-empty event_id"));
            }
            if claims.sub.is_empty()
                || claims.sub.len() > MAX_EVENT_SUB_LEN
                || claims.sub.chars().any(char::is_control)
            {
                return Err(Invalid("malformed sub"));
            }
            Ok(ChirpEvent::UserDeleted {
                sub: claims.sub,
                event_id: claims.event_id,
                deleted_at: claims.deleted_at,
            })
        }
        _ => Err(Invalid("unsupported event type")),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use serde_json::json;

    use super::*;
    use crate::testkit::{user_deleted_claims, JwksServer, TestSigningKey};

    const APP: &str = "cs_test_app";
    const KID: &str = "event_test_1";

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    fn audiences(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    /// A JWKS server publishing `key`, and a config whose issuer is that server.
    async fn setup(key: &TestSigningKey) -> (JwksServer, ChirpAuthConfig) {
        let server = JwksServer::start(vec![key.jwk()]).await;
        let config = ChirpAuthConfig::new(server.issuer(), APP);
        (server, config)
    }

    async fn verify(config: &ChirpAuthConfig, token: &str) -> Result<ChirpEvent, EventRejection> {
        verify_chirp_event(&reqwest::Client::new(), config, token, &audiences(&[APP])).await
    }

    fn event(
        key: &TestSigningKey,
        issuer: &str,
        claims_edit: impl FnOnce(&mut serde_json::Value),
    ) -> String {
        let mut claims = user_deleted_claims(issuer, APP, "sub_pairwise_1", "evt_1", now());
        claims_edit(&mut claims);
        key.sign_event(&claims)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accepts_a_genuine_user_deleted_event() {
        let key = TestSigningKey::new(KID);
        let (server, config) = setup(&key).await;
        let mut claims =
            user_deleted_claims(server.issuer(), APP, "sub_pairwise_1", "evt_1", now());
        claims["deleted_at"] = json!(1_700_000_000);
        // Surrounding whitespace (a trailing newline in a body) is ignored.
        let token = format!("{}\n", key.sign_event(&claims));
        assert_eq!(
            verify(&config, &token).await,
            Ok(ChirpEvent::UserDeleted {
                sub: "sub_pairwise_1".into(),
                event_id: "evt_1".into(),
                deleted_at: 1_700_000_000,
            })
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn garbage_and_wrong_header_classes_never_fetch_keys() {
        let key = TestSigningKey::new(KID);
        let (server, config) = setup(&key).await;
        let claims = user_deleted_claims(server.issuer(), APP, "s", "e", now());
        let cases = [
            "".to_owned(),
            "not a jwt".to_owned(),
            "a.b".to_owned(),
            "a.b.c.d".to_owned(),
            "!!.!!.!!".to_owned(),
            // An ID token, a keybind cert, no typ, and HS256: all refused on the header.
            key.sign(
                &json!({"alg": "RS256", "typ": crate::ID_TOKEN_TYP, "kid": KID}),
                &claims,
            ),
            key.sign(
                &json!({"alg": "RS256", "typ": crate::KEYBIND_TYP, "kid": KID}),
                &claims,
            ),
            key.sign(&json!({"alg": "RS256", "kid": KID}), &claims),
            key.sign(
                &json!({"alg": "HS256", "typ": EVENT_TYP, "kid": KID}),
                &claims,
            ),
        ];
        for token in cases {
            assert!(
                matches!(
                    verify(&config, &token).await,
                    Err(EventRejection::Unverified(_))
                ),
                "{token}"
            );
        }
        assert_eq!(server.hits(), 0, "no case may cost a key fetch");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_signature_or_unknown_key_is_unverified() {
        let key = TestSigningKey::new(KID);
        let (server, config) = setup(&key).await;

        // Signed by a different key under the published kid.
        let forged = event(&TestSigningKey::other(KID), server.issuer(), |_| {});
        assert_eq!(
            verify(&config, &forged).await,
            Err(EventRejection::Unverified("bad signature"))
        );

        // A kid the set doesn't hold.
        let unknown = event(
            &TestSigningKey::other("event_unknown"),
            server.issuer(),
            |_| {},
        );
        assert_eq!(
            verify(&config, &unknown).await,
            Err(EventRejection::Unverified("no event key with this kid"))
        );

        // Claims tampered after signing.
        let token = event(&key, server.issuer(), |_| {});
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_claims = URL_SAFE_NO_PAD.encode(
            user_deleted_claims(server.issuer(), APP, "someone_else", "evt_1", now()).to_string(),
        );
        parts[1] = &tampered_claims;
        assert_eq!(
            verify(&config, &parts.join(".")).await,
            Err(EventRejection::Unverified("bad signature"))
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn iat_is_bounded_on_both_sides() {
        let key = TestSigningKey::new(KID);
        let (server, config) = setup(&key).await;
        let at = |iat: i64| event(&key, server.issuer(), move |c| c["iat"] = json!(iat));
        let window = Err(EventRejection::Unverified(
            "iat outside the accepted window",
        ));

        // Margins of a few seconds keep these off the exact boundary while the
        // test runs.
        assert!(verify(&config, &at(now() - MAX_EVENT_AGE_SECS + 5))
            .await
            .is_ok());
        assert!(verify(&config, &at(now() + MAX_EVENT_CLOCK_SKEW_SECS - 5))
            .await
            .is_ok());
        assert_eq!(
            verify(&config, &at(now() - MAX_EVENT_AGE_SECS - 5)).await,
            window
        );
        assert_eq!(
            verify(&config, &at(now() + MAX_EVENT_CLOCK_SKEW_SECS + 5)).await,
            window
        );
        assert_eq!(verify(&config, &at(0)).await, window);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audience_issuer_and_client_id_must_match() {
        let key = TestSigningKey::new(KID);
        let (server, config) = setup(&key).await;
        let not_addressed = Err(EventRejection::Unverified(
            "not addressed to an accepted audience",
        ));

        let other_app = event(&key, server.issuer(), |c| {
            c["aud"] = json!("cs_test_other");
            c["client_id"] = json!("cs_test_other");
        });
        assert_eq!(verify(&config, &other_app).await, not_addressed);
        // The same token verifies for a receiver that accepts that audience.
        assert!(verify_chirp_event(
            &reqwest::Client::new(),
            &config,
            &other_app,
            &audiences(&[APP, "cs_test_other"])
        )
        .await
        .is_ok());
        // An empty audience set accepts nothing.
        let genuine = event(&key, server.issuer(), |_| {});
        assert_eq!(
            verify_chirp_event(&reqwest::Client::new(), &config, &genuine, &BTreeSet::new()).await,
            not_addressed
        );

        let mismatched_client = event(&key, server.issuer(), |c| {
            c["client_id"] = json!("cs_test_other")
        });
        assert_eq!(verify(&config, &mismatched_client).await, not_addressed);

        let wrong_issuer = event(&key, "https://signin.elsewhere.example", |_| {});
        assert_eq!(
            verify(&config, &wrong_issuer).await,
            Err(EventRejection::Unverified("wrong issuer"))
        );
    }

    /// A claims edit and the `Invalid` reason it must produce.
    type Case = (fn(&mut serde_json::Value), &'static str);

    #[tokio::test(flavor = "multi_thread")]
    async fn signed_but_unusable_events_are_invalid() {
        let key = TestSigningKey::new(KID);
        let (server, config) = setup(&key).await;
        let cases: [Case; 9] = [
            (
                |c| c["type"] = json!("user.renamed"),
                "unsupported event type",
            ),
            (
                |c| c["jti"] = json!("evt_other"),
                "jti must equal a non-empty event_id",
            ),
            (
                |c| {
                    c["jti"] = json!("");
                    c["event_id"] = json!("");
                },
                "jti must equal a non-empty event_id",
            ),
            (|c| c["sub"] = json!(""), "malformed sub"),
            (
                |c| c["sub"] = json!("a".repeat(MAX_EVENT_SUB_LEN + 1)),
                "malformed sub",
            ),
            (
                |c| c["sub"] = json!("sub\nInjected: header"),
                "malformed sub",
            ),
            (|c| c["sub"] = json!("sub\u{7f}"), "malformed sub"),
            (|c| c["deleted_at"] = json!("yesterday"), "bad claims"),
            (
                |c| {
                    c.as_object_mut().unwrap().remove("iat");
                },
                "bad claims",
            ),
        ];
        for (edit, reason) in cases {
            let token = event(&key, server.issuer(), edit);
            assert_eq!(
                verify(&config, &token).await,
                Err(EventRejection::Invalid(reason)),
                "{reason}"
            );
        }
        // The longest allowed sub passes.
        let longest = event(&key, server.issuer(), |c| {
            c["sub"] = json!("a".repeat(MAX_EVENT_SUB_LEN))
        });
        assert!(verify(&config, &longest).await.is_ok());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_key_set_is_keys_unavailable() {
        // Bind then drop a listener: the port is (almost certainly) closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let config = ChirpAuthConfig::new(&issuer, APP);
        let token = event(&TestSigningKey::new(KID), &issuer, |_| {});
        assert!(matches!(
            verify(&config, &token).await,
            Err(EventRejection::KeysUnavailable(_))
        ));
    }

    /// ChirpAuth mints its event key on first use. A receiver that fetched the
    /// set before that (empty, or holding only an older key) must still accept
    /// an event signed by the new key: the unknown kid refetches.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_key_minted_after_the_first_fetch_verifies() {
        let clock = Arc::new(AtomicI64::new(1_000_000));
        let reading = clock.clone();
        let cache = JwksCache::with_clock(Arc::new(move || {
            SystemTime::UNIX_EPOCH + Duration::from_secs(reading.load(Ordering::SeqCst) as u64)
        }));
        let server = JwksServer::start(Vec::new()).await;
        let config = ChirpAuthConfig::new(server.issuer(), APP);
        let http = reqwest::Client::new();
        let key = TestSigningKey::new(KID);
        let token = event(&key, server.issuer(), |_| {});
        let run = |token: String| {
            let (cache, http, config) = (&cache, &http, &config);
            async move { verify_with(cache, http, config, &token, &audiences(&[APP]), now()).await }
        };

        // A probe before the key exists caches the empty set.
        assert_eq!(
            run(token.clone()).await,
            Err(EventRejection::Unverified("no event key with this kid"))
        );
        assert_eq!(server.hits(), 1);

        // ChirpAuth mints the key. Within the refetch floor the cached set still
        // answers (a flood of forged kids costs no fetches)...
        server.set_keys(vec![key.jwk()]);
        clock.fetch_add(10, Ordering::SeqCst);
        assert!(run(token.clone()).await.is_err());
        assert_eq!(server.hits(), 1);

        // ...and by ChirpAuth's first retry (60 s later) it refetches and verifies.
        clock.fetch_add(50, Ordering::SeqCst);
        assert!(run(token.clone()).await.is_ok());
        assert_eq!(server.hits(), 2);
    }
}
