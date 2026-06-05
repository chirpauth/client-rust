//! Machine-token minting for confidential clients (the `client_credentials`
//! grant), with a positive token cache, a credential-keyed negative cache, and
//! capped exponential backoff on permanent rejections.
//!
//! Why this exists: a confidential client that mints on a fixed schedule (a
//! cron tick, a poll loop) using a bad/stale/deleted credential will otherwise
//! hammer the issuer's `/token` forever — a fresh `invalid_client` every tick.
//! The negative cache turns "wrong forever" from thousands of failed calls per
//! day into a handful, while never *silencing* the error: every permanent
//! rejection is returned as [`MintError::Rejected`]. Surface it / alarm on it —
//! the cache reduces volume, not visibility.
//!
//! The negative cache is keyed by a fingerprint of `(client_id, client_secret)`,
//! so changing the credential is an automatic cache miss: a fixed credential is
//! retried only on the backoff schedule, but a *new* credential is tried
//! immediately. ChirpAuth also guarantees client_ids are single-use, so a
//! recovered client always carries a new id ⇒ a new fingerprint ⇒ an instant
//! retry. The only case the fingerprint can't catch — the same credential being
//! made valid again server-side — is bounded by `negative_cap` (the backoff
//! ceiling), after which the client re-probes on its own.
//!
//! Transient failures (HTTP 5xx/429, network, timeout) are NOT negative-cached;
//! they are reported as [`MintError::Transient`] and retried on the next call.

use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// Tuning knobs for the caches and backoff. [`Default`] is production-sane.
#[derive(Clone, Debug)]
pub struct MintPolicy {
    /// Re-mint this long before the cached token's stated expiry, so callers
    /// never present an about-to-expire token.
    pub refresh_skew: Duration,
    /// Backoff after the first permanent rejection. Doubles with each
    /// consecutive rejection, capped at `negative_cap`.
    pub negative_base: Duration,
    /// Ceiling on the permanent-rejection backoff. Also bounds how long a client
    /// stays suppressed after a same-credential server-side fix.
    pub negative_cap: Duration,
    /// Assumed token lifetime when the issuer omits `expires_in`.
    pub default_lifetime: Duration,
}

impl Default for MintPolicy {
    fn default() -> Self {
        Self {
            refresh_skew: Duration::from_secs(60),
            negative_base: Duration::from_secs(60),
            negative_cap: Duration::from_secs(3600),
            default_lifetime: Duration::from_secs(600),
        }
    }
}

/// Identifies and authenticates the confidential client to mint tokens for.
#[derive(Clone)]
pub struct MintConfig {
    /// Issuer base URL, e.g. `https://signin.chirpauth.com` (trailing slash ok).
    pub issuer: String,
    /// The confidential client's id.
    pub client_id: String,
    /// The confidential client's secret.
    pub client_secret: String,
    /// Cache/backoff tuning.
    pub policy: MintPolicy,
}

impl MintConfig {
    /// Build a config with the default [`MintPolicy`].
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            policy: MintPolicy::default(),
        }
    }
}

/// Why a [`MachineTokenMinter::token`] call did not return a token.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    /// The issuer rejected the credentials (HTTP 4xx other than 429).
    /// **Permanent** — the credential is wrong/stale/retired and will not start
    /// working on its own. Callers MUST surface this (log/metric/alarm) and must
    /// not retry in a tight loop; the minter has recorded a backoff so further
    /// calls inside the window return [`MintError::Suppressed`] with no network
    /// hit.
    #[error("issuer rejected client credentials (permanent): {0}")]
    Rejected(String),
    /// A recent permanent rejection is still within its backoff window; no
    /// request was sent. `retry_after` is the remaining wait.
    #[error("minting suppressed for {retry_after:?} after a permanent rejection")]
    Suppressed {
        /// Remaining time until the next attempt is allowed.
        retry_after: Duration,
    },
    /// Transient failure (HTTP 5xx/429, network, timeout, or an unreadable
    /// success body). NOT negative-cached; the next call retries.
    #[error("transient mint failure: {0}")]
    Transient(String),
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Internal cache state. One minter holds one of these behind a `Mutex`.
enum State {
    Empty,
    /// A live token good until `expires_at` (already adjusted for `refresh_skew`).
    Valid {
        token: String,
        expires_at: Instant,
        fingerprint: u64,
    },
    /// The credential identified by `fingerprint` was rejected; suppress further
    /// attempts *with those credentials* until `until`.
    Rejected {
        fingerprint: u64,
        until: Instant,
        consecutive: u32,
    },
}

/// What the cache says to do before any network call.
#[derive(Debug, PartialEq)]
enum CacheDecision {
    Serve(String),
    Suppress(Duration),
    Mint,
}

/// Pure: decide, from current state, whether to serve a cached token, suppress
/// (still inside a rejection backoff for the *same* credential), or mint. A
/// rejection for a *different* fingerprint never suppresses — that's the
/// credential-keyed invalidation that makes a changed credential an instant
/// retry.
fn decide(state: &State, fingerprint: u64, now: Instant) -> CacheDecision {
    match state {
        State::Valid {
            token,
            expires_at,
            fingerprint: fp,
        } if *fp == fingerprint && now < *expires_at => CacheDecision::Serve(token.clone()),
        State::Rejected {
            fingerprint: fp,
            until,
            ..
        } if *fp == fingerprint && now < *until => CacheDecision::Suppress(*until - now),
        // Empty, expired token, a different-credential entry, or an elapsed
        // backoff: mint.
        _ => CacheDecision::Mint,
    }
}

/// Outcome of an attempted mint, classified from the HTTP response.
enum Outcome {
    Success {
        id_token: String,
        expires_in: Option<u64>,
    },
    Permanent(String),
    Transient(String),
}

/// Pure: fold a mint outcome into the next state and the result to return.
/// Returns `None` for the state when it must be left untouched (transient
/// failures must not drop a still-valid token or create a negative entry).
fn apply(
    prev: &State,
    fingerprint: u64,
    now: Instant,
    outcome: Outcome,
    policy: &MintPolicy,
) -> (Option<State>, Result<String, MintError>) {
    match outcome {
        Outcome::Success {
            id_token,
            expires_in,
        } => {
            let lifetime = expires_in
                .map(Duration::from_secs)
                .unwrap_or(policy.default_lifetime);
            let expires_at = now + lifetime.saturating_sub(policy.refresh_skew);
            (
                Some(State::Valid {
                    token: id_token.clone(),
                    expires_at,
                    fingerprint,
                }),
                Ok(id_token),
            )
        }
        Outcome::Permanent(msg) => {
            // Count consecutive permanent rejections for THIS credential so the
            // backoff grows; a different fingerprint restarts the count.
            let consecutive = match prev {
                State::Rejected {
                    fingerprint: fp,
                    consecutive,
                    ..
                } if *fp == fingerprint => consecutive.saturating_add(1),
                _ => 1,
            };
            (
                Some(State::Rejected {
                    fingerprint,
                    until: now + backoff_for(consecutive, policy),
                    consecutive,
                }),
                Err(MintError::Rejected(msg)),
            )
        }
        // Leave state untouched: don't negative-cache, don't drop a live token.
        Outcome::Transient(msg) => (None, Err(MintError::Transient(msg))),
    }
}

/// `negative_base * 2^(consecutive - 1)`, capped at `negative_cap`, saturating.
fn backoff_for(consecutive: u32, policy: &MintPolicy) -> Duration {
    let shift = consecutive.saturating_sub(1).min(31);
    let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
    policy
        .negative_base
        .checked_mul(factor)
        .unwrap_or(policy.negative_cap)
        .min(policy.negative_cap)
}

/// In-memory fingerprint of a credential pair. Not cryptographic — only used to
/// detect that the credential changed, so the negative cache can be bypassed.
fn fingerprint(client_id: &str, client_secret: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    client_id.hash(&mut h);
    0xffu8.hash(&mut h); // domain separator so id|secret ≠ different split
    client_secret.hash(&mut h);
    h.finish()
}

fn truncate(s: &str) -> String {
    const MAX: usize = 200;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}…", &s[..MAX])
    }
}

/// Mints and caches `client_credentials` machine tokens for one confidential
/// client. Cheap to clone the config in; hold one minter per client for the
/// process lifetime so the caches are shared. `token()` is safe to call
/// concurrently.
pub struct MachineTokenMinter {
    config: MintConfig,
    http: reqwest::Client,
    state: Mutex<State>,
}

impl MachineTokenMinter {
    /// Build a minter with a fresh internal HTTP client.
    pub fn new(config: MintConfig) -> Self {
        Self::with_http_client(config, reqwest::Client::new())
    }

    /// Build a minter reusing a caller-provided HTTP client (connection pools,
    /// timeouts, proxies). A request timeout on the client is recommended so a
    /// hung issuer surfaces as [`MintError::Transient`] rather than blocking.
    pub fn with_http_client(config: MintConfig, http: reqwest::Client) -> Self {
        Self {
            config,
            http,
            state: Mutex::new(State::Empty),
        }
    }

    /// Return a valid machine ID token, minting only when the cache can't serve
    /// one. Serves a cached token when fresh; fails fast with
    /// [`MintError::Suppressed`] when inside a post-rejection backoff (no network
    /// hit); otherwise mints. See the module docs for the failure semantics.
    pub async fn token(&self) -> Result<String, MintError> {
        let fp = fingerprint(&self.config.client_id, &self.config.client_secret);

        // Phase 1: consult the cache. Lock is released before any await.
        {
            let state = self.state.lock().expect("mint cache mutex poisoned");
            match decide(&state, fp, Instant::now()) {
                CacheDecision::Serve(token) => return Ok(token),
                CacheDecision::Suppress(retry_after) => {
                    return Err(MintError::Suppressed { retry_after })
                }
                CacheDecision::Mint => {}
            }
        }

        // Phase 2: mint over the network (no lock held).
        let outcome = self.request().await;

        // Phase 3: fold the outcome into the cache.
        let mut state = self.state.lock().expect("mint cache mutex poisoned");
        let (next, result) = apply(&state, fp, Instant::now(), outcome, &self.config.policy);
        if let Some(next) = next {
            *state = next;
        }
        result
    }

    async fn request(&self) -> Outcome {
        let url = format!("{}/token", self.config.issuer.trim_end_matches('/'));
        let resp = self
            .http
            .post(&url)
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .header("content-type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await;
        let resp = match resp {
            Ok(resp) => resp,
            Err(err) => return Outcome::Transient(format!("request error: {err}")),
        };
        let status = resp.status();
        if status.is_success() {
            match resp.json::<TokenResponse>().await {
                Ok(body) => Outcome::Success {
                    id_token: body.id_token,
                    expires_in: body.expires_in,
                },
                // A 2xx with an unreadable body isn't a credential problem;
                // treat as transient so we retry rather than suppress.
                Err(err) => Outcome::Transient(format!("unreadable token response: {err}")),
            }
        } else if status.as_u16() == 429 {
            // Rate limiting is transient, not a credential rejection.
            Outcome::Transient("HTTP 429 (rate limited)".to_string())
        } else if status.is_client_error() {
            let body = resp.text().await.unwrap_or_default();
            Outcome::Permanent(format!("HTTP {status}: {}", truncate(&body)))
        } else {
            Outcome::Transient(format!("HTTP {status}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> MintPolicy {
        MintPolicy {
            refresh_skew: Duration::from_secs(60),
            negative_base: Duration::from_secs(60),
            negative_cap: Duration::from_secs(3600),
            default_lifetime: Duration::from_secs(600),
        }
    }

    // ---- decide() ----

    #[test]
    fn decide_empty_mints() {
        assert_eq!(decide(&State::Empty, 1, Instant::now()), CacheDecision::Mint);
    }

    #[test]
    fn decide_serves_fresh_token_for_same_fingerprint() {
        let now = Instant::now();
        let state = State::Valid {
            token: "tok".into(),
            expires_at: now + Duration::from_secs(100),
            fingerprint: 7,
        };
        assert_eq!(decide(&state, 7, now), CacheDecision::Serve("tok".into()));
    }

    #[test]
    fn decide_mints_when_token_expired_or_fingerprint_changed() {
        let now = Instant::now();
        let expired = State::Valid {
            token: "tok".into(),
            expires_at: now,
            fingerprint: 7,
        };
        assert_eq!(decide(&expired, 7, now + Duration::from_secs(1)), CacheDecision::Mint);
        let other_cred = State::Valid {
            token: "tok".into(),
            expires_at: now + Duration::from_secs(100),
            fingerprint: 7,
        };
        // Different credential ⇒ the cached token is irrelevant ⇒ mint.
        assert_eq!(decide(&other_cred, 8, now), CacheDecision::Mint);
    }

    #[test]
    fn decide_suppresses_within_backoff_for_same_fingerprint() {
        let now = Instant::now();
        let state = State::Rejected {
            fingerprint: 7,
            until: now + Duration::from_secs(30),
            consecutive: 1,
        };
        assert_eq!(decide(&state, 7, now), CacheDecision::Suppress(Duration::from_secs(30)));
    }

    #[test]
    fn decide_bypasses_rejection_for_a_changed_credential() {
        // The same-cred-fix escape hatch: a rejection entry must NOT suppress a
        // *different* credential. New fingerprint ⇒ mint immediately.
        let now = Instant::now();
        let state = State::Rejected {
            fingerprint: 7,
            until: now + Duration::from_secs(3000),
            consecutive: 5,
        };
        assert_eq!(decide(&state, 999, now), CacheDecision::Mint);
    }

    #[test]
    fn decide_mints_after_backoff_elapses() {
        let now = Instant::now();
        let state = State::Rejected {
            fingerprint: 7,
            until: now,
            consecutive: 1,
        };
        assert_eq!(decide(&state, 7, now + Duration::from_secs(1)), CacheDecision::Mint);
    }

    // ---- apply() ----

    #[test]
    fn apply_success_caches_token_with_skew() {
        let now = Instant::now();
        let (state, result) = apply(
            &State::Empty,
            7,
            now,
            Outcome::Success {
                id_token: "tok".into(),
                expires_in: Some(600),
            },
            &policy(),
        );
        assert_eq!(result.unwrap(), "tok");
        match state.unwrap() {
            State::Valid { token, expires_at, fingerprint } => {
                assert_eq!(token, "tok");
                assert_eq!(fingerprint, 7);
                // 600s lifetime - 60s skew = ~540s out.
                assert!(expires_at > now + Duration::from_secs(539));
                assert!(expires_at <= now + Duration::from_secs(540));
            }
            _ => panic!("expected Valid"),
        }
    }

    #[test]
    fn apply_permanent_backs_off_and_doubles() {
        let now = Instant::now();
        // First rejection: base backoff, consecutive = 1.
        let (s1, r1) = apply(&State::Empty, 7, now, Outcome::Permanent("invalid_client".into()), &policy());
        assert!(matches!(r1, Err(MintError::Rejected(_))));
        let s1 = s1.unwrap();
        match &s1 {
            State::Rejected { consecutive, until, fingerprint } => {
                assert_eq!(*consecutive, 1);
                assert_eq!(*fingerprint, 7);
                assert_eq!(*until, now + Duration::from_secs(60));
            }
            _ => panic!("expected Rejected"),
        }
        // Second consecutive rejection (same fp): doubled backoff, consecutive = 2.
        let (s2, _) = apply(&s1, 7, now, Outcome::Permanent("invalid_client".into()), &policy());
        match s2.unwrap() {
            State::Rejected { consecutive, until, .. } => {
                assert_eq!(consecutive, 2);
                assert_eq!(until, now + Duration::from_secs(120));
            }
            _ => panic!("expected Rejected"),
        }
    }

    #[test]
    fn apply_permanent_backoff_is_capped() {
        let now = Instant::now();
        let prev = State::Rejected {
            fingerprint: 7,
            until: now,
            consecutive: 20, // 60s * 2^20 would massively exceed the cap
        };
        let (s, _) = apply(&prev, 7, now, Outcome::Permanent("x".into()), &policy());
        match s.unwrap() {
            State::Rejected { until, .. } => assert_eq!(until, now + Duration::from_secs(3600)),
            _ => panic!("expected Rejected"),
        }
    }

    #[test]
    fn apply_transient_leaves_state_untouched() {
        let now = Instant::now();
        let (state, result) = apply(&State::Empty, 7, now, Outcome::Transient("5xx".into()), &policy());
        assert!(state.is_none(), "transient must not mutate cache state");
        assert!(matches!(result, Err(MintError::Transient(_))));
    }

    #[test]
    fn backoff_schedule() {
        let p = policy();
        assert_eq!(backoff_for(1, &p), Duration::from_secs(60));
        assert_eq!(backoff_for(2, &p), Duration::from_secs(120));
        assert_eq!(backoff_for(3, &p), Duration::from_secs(240));
        assert_eq!(backoff_for(100, &p), Duration::from_secs(3600)); // capped
    }

    #[test]
    fn fingerprint_changes_with_either_half() {
        let base = fingerprint("cs_live_a", "secret");
        assert_ne!(base, fingerprint("cs_live_b", "secret"));
        assert_ne!(base, fingerprint("cs_live_a", "secret2"));
        assert_eq!(base, fingerprint("cs_live_a", "secret"));
    }
}

#[cfg(test)]
mod io_tests {
    //! End-to-end tests that drive the real reqwest POST against a minimal
    //! in-process HTTP server, so the caching/suppression behaviour is verified
    //! through the actual network path, not just the pure decision functions.
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a one-route server that answers every connection with the same
    /// status line + JSON body, counting the connections it served. Returns the
    /// issuer base URL (no trailing slash) and the request counter.
    async fn start_token_server(
        status_line: &'static str,
        body: &'static str,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let served = count.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                served.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let resp = format!(
                        "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        (format!("http://{addr}"), count)
    }

    #[tokio::test]
    async fn serves_minted_token_then_caches_it() {
        let (issuer, count) =
            start_token_server("HTTP/1.1 200 OK", r#"{"id_token":"tok-1","expires_in":3600}"#).await;
        let minter = MachineTokenMinter::new(MintConfig::new(issuer, "cs_live_x", "secret"));
        assert_eq!(minter.token().await.unwrap(), "tok-1");
        assert_eq!(minter.token().await.unwrap(), "tok-1");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the second call must be served from cache, not re-minted"
        );
    }

    #[tokio::test]
    async fn suppresses_after_a_permanent_rejection() {
        let (issuer, count) =
            start_token_server("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_client"}"#).await;
        let minter = MachineTokenMinter::new(MintConfig::new(issuer, "cs_live_ghost", "secret"));
        // First call hits the issuer and is rejected (permanent).
        assert!(matches!(minter.token().await, Err(MintError::Rejected(_))));
        // Second call is suppressed by the negative cache — no network request.
        assert!(matches!(
            minter.token().await,
            Err(MintError::Suppressed { .. })
        ));
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "the suppressed call must not have hit the issuer"
        );
    }
}
