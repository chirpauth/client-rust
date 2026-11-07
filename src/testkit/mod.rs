//! Test support for code that verifies ChirpAuth-signed tokens: fixed signing
//! keys and an in-process JWKS server. Enabled by the `testkit` feature; use it
//! from `[dev-dependencies]` only.
//!
//! ```ignore
//! let key = TestSigningKey::new("event_test_1");
//! let server = JwksServer::start(vec![key.jwk()]).await;
//! let config = ChirpAuthConfig::new(server.issuer(), "cs_test_app");
//! let token = key.sign_event(&user_deleted_claims(server.issuer(), "cs_test_app", "sub_1", "evt_1", now));
//! ```
//!
//! The server is the issuer: it answers every path (so both `/jwks.json` and
//! `/events/jwks.json`) with the current key set. Each test should start its own
//! server, which gives it its own URL and so its own slot in the per-process
//! JWKS cache.
//!
//! The two keys are fixed 2048-bit RSA keys checked into this crate, so tests
//! spend no time generating keys. They are public: never trust them anywhere but
//! a test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::rsa::PublicKeyComponents;
use ring::signature::{KeyPair as _, RsaKeyPair, RSA_PKCS1_SHA256};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::events::{EVENT_TYP, USER_DELETED};
use crate::Jwk;

const KEY_A: &str = include_str!("key_a.der.b64");
const KEY_B: &str = include_str!("key_b.der.b64");

/// A fixed RSA signing key with a `kid`, for minting test tokens.
pub struct TestSigningKey {
    kid: String,
    pair: RsaKeyPair,
}

impl TestSigningKey {
    /// The primary test key under `kid`.
    pub fn new(kid: &str) -> Self {
        Self::load(KEY_A, kid)
    }

    /// A second, different key under `kid`: for "signed by a key the set doesn't
    /// hold" cases, or two keys in one set.
    pub fn other(kid: &str) -> Self {
        Self::load(KEY_B, kid)
    }

    fn load(der_b64: &str, kid: &str) -> Self {
        let der = URL_SAFE_NO_PAD
            .decode(der_b64.trim())
            .expect("testkit key is base64url");
        Self {
            kid: kid.to_owned(),
            pair: RsaKeyPair::from_der(&der).expect("testkit key is PKCS#1 DER"),
        }
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// This key's public half as a JWK (`kty: RSA`, `alg: RS256`).
    pub fn jwk(&self) -> Jwk {
        let public = PublicKeyComponents::<Vec<u8>>::from(self.pair.public_key());
        Jwk {
            kty: "RSA".to_owned(),
            kid: self.kid.clone(),
            alg: Some("RS256".to_owned()),
            n: URL_SAFE_NO_PAD.encode(&public.n),
            e: URL_SAFE_NO_PAD.encode(&public.e),
        }
    }

    /// A compact RS256 JWS of `header` and `claims`, as given. The header is not
    /// touched, so tests can sign deliberately wrong ones.
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.pair.public().modulus_len()];
        self.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                input.as_bytes(),
                &mut signature,
            )
            .expect("RSA signing");
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    /// An event token the way ChirpAuth signs one: `alg: RS256`,
    /// `typ: chirp-event+jwt`, and this key's `kid`.
    pub fn sign_event(&self, claims: &Value) -> String {
        self.sign(
            &json!({"alg": "RS256", "typ": EVENT_TYP, "kid": self.kid}),
            claims,
        )
    }
}

/// The claims of a `user.deleted` event, shaped exactly as ChirpAuth sends them
/// (chirp-auth `src/deletion_events.rs`, `UserDeletedClaims`), addressed to
/// `client_id`, signed at `iat`.
pub fn user_deleted_claims(
    issuer: &str,
    client_id: &str,
    sub: &str,
    event_id: &str,
    iat: i64,
) -> Value {
    json!({
        "iss": issuer,
        "aud": client_id,
        "iat": iat,
        "jti": event_id,
        "type": USER_DELETED,
        "sub": sub,
        "client_id": client_id,
        "deleted_at": iat - 5,
        "event_id": event_id,
    })
}

/// An in-process HTTP server that answers every request with a JWKS of the
/// current keys, and counts the requests. It runs until the test's runtime shuts
/// down.
pub struct JwksServer {
    issuer: String,
    keys: Arc<Mutex<Vec<Jwk>>>,
    hits: Arc<AtomicUsize>,
}

impl JwksServer {
    /// Start serving `keys` on a free 127.0.0.1 port. Needs a Tokio runtime.
    pub async fn start(keys: Vec<Jwk>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local port");
        let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
        let keys = Arc::new(Mutex::new(keys));
        let hits = Arc::new(AtomicUsize::new(0));
        let (served, counted) = (keys.clone(), hits.clone());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let body = jwks_body(&served.lock().unwrap_or_else(PoisonError::into_inner));
                tokio::spawn(async move {
                    let mut request = vec![0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { issuer, keys, hits }
    }

    /// The server's base URL (`http://127.0.0.1:<port>`): use it as the issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Replace the published keys, e.g. to model a key minted or rotated mid-test.
    pub fn set_keys(&self, keys: Vec<Jwk>) {
        *self.keys.lock().unwrap_or_else(PoisonError::into_inner) = keys;
    }

    /// Requests served so far.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn jwks_body(keys: &[Jwk]) -> String {
    let keys: Vec<Value> = keys
        .iter()
        .map(|key| json!({"kty": key.kty, "kid": key.kid, "alg": key.alg, "n": key.n, "e": key.e}))
        .collect();
    json!({ "keys": keys }).to_string()
}
