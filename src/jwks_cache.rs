//! Per-process JWKS cache behind every verify call.
//!
//! Before 0.17 each verify fetched `{issuer}/jwks.json`, so a relying party's
//! request rate WAS its load on ChirpAuth: a parallel burst at one consumer
//! (Jot's export, ~70 rps) tripped ChirpAuth's API-Gateway throttle and turned
//! valid tokens into failures. Keys rotate on the order of days, so every one of
//! those fetches but the first was redundant.
//!
//! The cache changes WHEN keys are fetched, never WHICH keys are trusted: a
//! verify still trusts exactly the keys in a JWKS document ChirpAuth served for
//! this URL, at most [`MAX_AGE_CAP`] ago. The rules:
//!
//! - **Hit.** A fresh keyset that contains the token's `kid` is used without any
//!   network call.
//! - **Expiry.** A keyset is fresh for the response's `Cache-Control: max-age`,
//!   clamped to [`MIN_REFRESH_INTERVAL`]..=[`MAX_AGE_CAP`] (no header →
//!   [`MAX_AGE_CAP`]). After that, the next verify refetches. This is the
//!   revocation bound: a `kid` removed from the JWKS stops verifying in every
//!   process within the effective max-age (300 s for ChirpAuth today, never
//!   more than 10 min). `stale-while-revalidate` is deliberately NOT honoured —
//!   serving a stale keyset would stretch that bound.
//! - **Unknown kid.** A fresh keyset without the token's `kid` (e.g. right after
//!   ChirpAuth rotates, since a new key signs immediately) is refetched once —
//!   but only if it is at least [`MIN_REFRESH_INTERVAL`] old. A flood of forged
//!   kids therefore costs at most one fetch per interval per process, not one per
//!   request. The price is that a token signed by a key born less than
//!   [`MIN_REFRESH_INTERVAL`] after this process's last fetch is rejected
//!   (`NoMatchingKey`) until the interval passes.
//! - **Single flight.** Concurrent misses on one URL share one fetch: callers
//!   queue behind it and take its outcome — keys or error — instead of each
//!   fetching. A burst of N cold verifies is one request to ChirpAuth.
//! - **Failure is loud.** A failed fetch is never papered over with stale keys;
//!   it surfaces as [`ChirpAuthError::JwksFetch`], which callers can (and should)
//!   map to "upstream unavailable" (503), distinct from a bad token (401).
//!   Failures are not cached: the next caller after a failed attempt tries again.
//!
//! Freshness is measured on the wall clock (`SystemTime`), the same clock token
//! `exp` is checked against. A clock that steps backwards makes a keyset look
//! stale and triggers a refetch — the safe direction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, SystemTime};

use crate::{ChirpAuthError, Jwk, Jwks};

/// The longest a fetched keyset is trusted before it must be refetched, whatever
/// the server's `max-age` says. This is the upper bound on how long a `kid`
/// removed from the JWKS keeps verifying in an already-running process.
pub(crate) const MAX_AGE_CAP: Duration = Duration::from_secs(10 * 60);

/// The minimum age of a cached keyset before an unknown `kid` may trigger a
/// refetch, and the floor on the server's `max-age` (so `max-age=0` cannot turn
/// the cache back into a fetch-per-verify).
pub(crate) const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Bound on one JWKS fetch. Concurrent verifies queue behind an in-flight fetch,
/// so it must not be able to hang forever (a `reqwest::Client::new()` has no
/// timeout of its own).
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The process-wide cache the verify functions use.
pub(crate) fn global() -> &'static JwksCache {
    static CACHE: OnceLock<JwksCache> = OnceLock::new();
    CACHE.get_or_init(|| JwksCache::with_clock(Arc::new(SystemTime::now)))
}

pub(crate) struct JwksCache {
    slots: Mutex<HashMap<String, Arc<Slot>>>,
    clock: Clock,
}

/// One JWKS URL's cache entry.
#[derive(Default)]
struct Slot {
    state: Mutex<SlotState>,
    /// Held across a fetch: whoever holds it is THE fetch for this URL.
    refresh: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct SlotState {
    keyset: Option<CachedKeyset>,
    /// Completed fetch attempts. A caller that saw N before queueing on
    /// `refresh` and finds more than N after acquiring it knows a fetch finished
    /// while it waited, and shares that outcome instead of fetching again.
    attempts: u64,
    /// The error of the most recent attempt, if it failed.
    last_error: Option<String>,
}

struct CachedKeyset {
    jwks: Jwks,
    fetched_at: SystemTime,
    ttl: Duration,
}

impl CachedKeyset {
    fn age(&self, now: SystemTime) -> Option<Duration> {
        // `Err` = the clock stepped backwards past `fetched_at`; callers treat an
        // unknown age as "old" (refetch), never as "young" (trust longer).
        now.duration_since(self.fetched_at).ok()
    }

    fn is_fresh(&self, now: SystemTime) -> bool {
        self.age(now).is_some_and(|age| age < self.ttl)
    }

    fn may_refetch_for_unknown_kid(&self, now: SystemTime) -> bool {
        self.age(now).is_none_or(|age| age >= MIN_REFRESH_INTERVAL)
    }

    fn key(&self, kid: &str) -> Option<Jwk> {
        self.jwks
            .keys
            .iter()
            .find(|key| key.kid == kid && key.kty == "RSA")
            .cloned()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // No critical section in this module can panic midway, so a poisoned lock
    // still guards consistent data.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl JwksCache {
    pub(crate) fn with_clock(clock: Clock) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            clock,
        }
    }

    fn slot(&self, jwks_uri: &str) -> Arc<Slot> {
        lock(&self.slots)
            .entry(jwks_uri.to_owned())
            .or_default()
            .clone()
    }

    /// The RSA key `kid` from the JWKS at `jwks_uri`, served from cache when
    /// fresh. `NoMatchingKey` when the (fresh) keyset has no such key;
    /// `JwksFetch` when a needed fetch failed.
    pub(crate) async fn key(
        &self,
        client: &reqwest::Client,
        jwks_uri: &str,
        kid: &str,
    ) -> Result<Jwk, ChirpAuthError> {
        let slot = self.slot(jwks_uri);

        let attempts_seen = {
            let state = lock(&slot.state);
            if let Some(keyset) = state.keyset.as_ref() {
                if keyset.is_fresh((self.clock)()) {
                    if let Some(key) = keyset.key(kid) {
                        return Ok(key);
                    }
                }
            }
            state.attempts
        };

        let _refresh = slot.refresh.lock().await;
        {
            let state = lock(&slot.state);
            let now = (self.clock)();
            let fresh = state.keyset.as_ref().filter(|keyset| keyset.is_fresh(now));
            if state.attempts != attempts_seen {
                // A fetch completed while we queued: take its outcome.
                if let Some(error) = &state.last_error {
                    return Err(ChirpAuthError::JwksFetch(error.clone()));
                }
                if let Some(keyset) = fresh {
                    return keyset.key(kid).ok_or(ChirpAuthError::NoMatchingKey);
                }
            } else if let Some(keyset) = fresh {
                if let Some(key) = keyset.key(kid) {
                    return Ok(key);
                }
                if !keyset.may_refetch_for_unknown_kid(now) {
                    return Err(ChirpAuthError::NoMatchingKey);
                }
            }
        }

        let outcome = fetch_document(client, jwks_uri).await;
        let mut state = lock(&slot.state);
        state.attempts += 1;
        match outcome {
            Ok((jwks, max_age)) => {
                let keyset = CachedKeyset {
                    jwks,
                    fetched_at: (self.clock)(),
                    ttl: effective_ttl(max_age),
                };
                let key = keyset.key(kid);
                state.keyset = Some(keyset);
                state.last_error = None;
                key.ok_or(ChirpAuthError::NoMatchingKey)
            }
            Err(error) => {
                state.last_error = Some(error.clone());
                Err(ChirpAuthError::JwksFetch(error))
            }
        }
    }
}

/// How long a keyset fetched with `server_max_age` stays fresh.
fn effective_ttl(server_max_age: Option<Duration>) -> Duration {
    server_max_age.map_or(MAX_AGE_CAP, |max_age| {
        max_age.clamp(MIN_REFRESH_INTERVAL, MAX_AGE_CAP)
    })
}

/// The `max-age` directive of a `Cache-Control` header, if any.
fn cache_control_max_age(headers: &http::HeaderMap) -> Option<Duration> {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|directive| {
            let (name, value) = directive.trim().split_once('=')?;
            if !name.trim().eq_ignore_ascii_case("max-age") {
                return None;
            }
            value.trim().trim_matches('"').parse().ok().map(Duration::from_secs)
        })
}

/// One uncached fetch: the parsed JWKS plus the server's `max-age`. The error
/// is a display string so a failed attempt's outcome can be shared with every
/// caller queued behind it.
pub(crate) async fn fetch_document(
    client: &reqwest::Client,
    jwks_uri: &str,
) -> Result<(Jwks, Option<Duration>), String> {
    let response = client
        .get(jwks_uri)
        .timeout(FETCH_TIMEOUT)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|error| error.to_string())?;
    let max_age = cache_control_max_age(response.headers());
    let jwks = response
        .json::<Jwks>()
        .await
        .map_err(|error| error.to_string())?;
    Ok((jwks, max_age))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What the fake JWKS endpoint answers with; tests mutate it mid-test to
    /// model rotation, removal, and outages.
    #[derive(Clone)]
    struct Response {
        status: u16,
        kids: Vec<&'static str>,
        cache_control: Option<&'static str>,
        delay: Duration,
    }

    impl Response {
        fn kids(kids: &[&'static str]) -> Self {
            Self {
                status: 200,
                kids: kids.to_vec(),
                cache_control: Some("public, max-age=300, stale-while-revalidate=600"),
                delay: Duration::ZERO,
            }
        }
    }

    struct Server {
        url: String,
        hits: Arc<AtomicUsize>,
        response: Arc<Mutex<Response>>,
    }

    impl Server {
        async fn start(response: Response) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/jwks.json", listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let response = Arc::new(Mutex::new(response));
            let (task_hits, task_response) = (hits.clone(), response.clone());
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let hits = task_hits.clone();
                    let response = lock(&task_response).clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        hits.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(response.delay).await;
                        let keys: Vec<String> = response
                            .kids
                            .iter()
                            .map(|kid| {
                                format!(r#"{{"kty":"RSA","kid":"{kid}","alg":"RS256","n":"AQAB","e":"AQAB"}}"#)
                            })
                            .collect();
                        let body = format!(r#"{{"keys":[{}]}}"#, keys.join(","));
                        let cache_control = response
                            .cache_control
                            .map(|value| format!("Cache-Control: {value}\r\n"))
                            .unwrap_or_default();
                        let reply = format!(
                            "HTTP/1.1 {} X\r\nContent-Type: application/json\r\n{cache_control}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            response.status,
                            body.len(),
                        );
                        let _ = stream.write_all(reply.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            Self {
                url,
                hits,
                response,
            }
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        fn set(&self, response: Response) {
            *lock(&self.response) = response;
        }
    }

    /// A cache on a hand-advanced clock, so expiry tests don't sleep.
    struct Fixture {
        cache: Arc<JwksCache>,
        offset_secs: Arc<AtomicI64>,
        client: reqwest::Client,
    }

    impl Fixture {
        fn new() -> Self {
            let base = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
            let offset_secs = Arc::new(AtomicI64::new(0));
            let clock_offset = offset_secs.clone();
            let clock: Clock = Arc::new(move || {
                let offset = clock_offset.load(Ordering::SeqCst);
                if offset >= 0 {
                    base + Duration::from_secs(offset as u64)
                } else {
                    base - Duration::from_secs(offset.unsigned_abs())
                }
            });
            Self {
                cache: Arc::new(JwksCache::with_clock(clock)),
                offset_secs,
                client: reqwest::Client::new(),
            }
        }

        fn set_time(&self, secs: i64) {
            self.offset_secs.store(secs, Ordering::SeqCst);
        }

        async fn key(&self, server: &Server, kid: &str) -> Result<Jwk, ChirpAuthError> {
            self.cache.key(&self.client, &server.url, kid).await
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fresh_keyset_serves_repeat_lookups_without_refetching() {
        let server = Server::start(Response::kids(&["a", "b"])).await;
        let fx = Fixture::new();
        for _ in 0..20 {
            assert_eq!(fx.key(&server, "a").await.unwrap().kid, "a");
            assert_eq!(fx.key(&server, "b").await.unwrap().kid, "b");
        }
        assert_eq!(server.hits(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn caches_are_per_url() {
        let first = Server::start(Response::kids(&["a"])).await;
        let second = Server::start(Response::kids(&["b"])).await;
        let fx = Fixture::new();
        fx.key(&first, "a").await.unwrap();
        // `a` is cached for `first`'s URL only: `second` does not trust it.
        assert!(matches!(
            fx.key(&second, "a").await,
            Err(ChirpAuthError::NoMatchingKey)
        ));
        assert_eq!(fx.key(&second, "b").await.unwrap().kid, "b");
        assert_eq!((first.hits(), second.hits()), (1, 1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_kid_refetches_once_the_min_interval_has_passed() {
        let server = Server::start(Response::kids(&["old"])).await;
        let fx = Fixture::new();
        fx.key(&server, "old").await.unwrap();

        // ChirpAuth rotates: the new key signs immediately.
        server.set(Response::kids(&["new", "old"]));
        fx.set_time(MIN_REFRESH_INTERVAL.as_secs() as i64);
        assert_eq!(fx.key(&server, "new").await.unwrap().kid, "new");
        assert_eq!(server.hits(), 2);
        // The retired key is still published (grace window), so still trusted.
        assert_eq!(fx.key(&server, "old").await.unwrap().kid, "old");
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn forged_kids_within_the_min_interval_cost_no_fetches() {
        let server = Server::start(Response::kids(&["real"])).await;
        let fx = Fixture::new();
        fx.key(&server, "real").await.unwrap();
        fx.set_time(MIN_REFRESH_INTERVAL.as_secs() as i64 - 1);
        for n in 0..100 {
            let forged = format!("forged-{n}");
            assert!(matches!(
                fx.key(&server, &forged).await,
                Err(ChirpAuthError::NoMatchingKey)
            ));
        }
        assert_eq!(server.hits(), 1);

        // Past the interval: one refetch, after which the forgeries are bounded
        // again by the new keyset's age.
        fx.set_time(MIN_REFRESH_INTERVAL.as_secs() as i64);
        for n in 0..100 {
            let forged = format!("forged-{n}");
            assert!(fx.key(&server, &forged).await.is_err());
        }
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_cold_lookups_share_one_fetch() {
        let mut response = Response::kids(&["a"]);
        response.delay = Duration::from_millis(300);
        let server = Server::start(response).await;
        let fx = Fixture::new();
        let tasks: Vec<_> = (0..64)
            .map(|_| {
                let (cache, client, url) = (fx.cache.clone(), fx.client.clone(), server.url.clone());
                tokio::spawn(async move { cache.key(&client, &url, "a").await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap().unwrap().kid, "a");
        }
        assert_eq!(server.hits(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_unknown_kid_lookups_share_one_refetch() {
        let server = Server::start(Response::kids(&["old"])).await;
        let fx = Fixture::new();
        fx.key(&server, "old").await.unwrap();
        let mut rotated = Response::kids(&["new", "old"]);
        rotated.delay = Duration::from_millis(300);
        server.set(rotated);
        fx.set_time(MIN_REFRESH_INTERVAL.as_secs() as i64);
        let tasks: Vec<_> = (0..64)
            .map(|i| {
                let (cache, client, url) = (fx.cache.clone(), fx.client.clone(), server.url.clone());
                // Half want the new key, half a forged one: still one fetch.
                let kid = if i % 2 == 0 { "new" } else { "forged" };
                tokio::spawn(async move { (kid, cache.key(&client, &url, kid).await) })
            })
            .collect();
        for task in tasks {
            match task.await.unwrap() {
                ("new", result) => assert_eq!(result.unwrap().kid, "new"),
                (_, result) => assert!(matches!(result, Err(ChirpAuthError::NoMatchingKey))),
            }
        }
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_removed_kid_stops_verifying_when_the_max_age_expires() {
        // ChirpAuth sends max-age=300.
        let server = Server::start(Response::kids(&["revoked", "kept"])).await;
        let fx = Fixture::new();
        fx.key(&server, "revoked").await.unwrap();

        server.set(Response::kids(&["kept"]));
        fx.set_time(299);
        // Inside the window the cached keyset still trusts it: the documented
        // revocation bound, not a bug.
        assert!(fx.key(&server, "revoked").await.is_ok());
        assert_eq!(server.hits(), 1);

        fx.set_time(300);
        assert!(matches!(
            fx.key(&server, "revoked").await,
            Err(ChirpAuthError::NoMatchingKey)
        ));
        assert_eq!(server.hits(), 2);
        assert!(fx.key(&server, "kept").await.is_ok());
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_server_max_age_is_clamped_and_defaults_to_the_cap() {
        for (cache_control, ttl) in [
            (Some("max-age=86400"), MAX_AGE_CAP),
            (None, MAX_AGE_CAP),
            (Some("no-cache, max-age=0"), MIN_REFRESH_INTERVAL),
            (Some("public, MAX-AGE=\"120\""), Duration::from_secs(120)),
        ] {
            let mut response = Response::kids(&["a"]);
            response.cache_control = cache_control;
            let server = Server::start(response).await;
            let fx = Fixture::new();
            fx.key(&server, "a").await.unwrap();
            fx.set_time(ttl.as_secs() as i64 - 1);
            fx.key(&server, "a").await.unwrap();
            assert_eq!(server.hits(), 1, "{cache_control:?}: still fresh before ttl");
            fx.set_time(ttl.as_secs() as i64);
            fx.key(&server, "a").await.unwrap();
            assert_eq!(server.hits(), 2, "{cache_control:?}: refetched at ttl");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_clock_stepping_backwards_refetches_rather_than_trusting_longer() {
        let server = Server::start(Response::kids(&["a"])).await;
        let fx = Fixture::new();
        fx.key(&server, "a").await.unwrap();
        fx.set_time(-1);
        fx.key(&server, "a").await.unwrap();
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_fetch_is_a_jwks_fetch_error_not_a_bad_token() {
        let mut throttled = Response::kids(&["a"]);
        throttled.status = 429;
        let server = Server::start(throttled).await;
        let fx = Fixture::new();
        assert!(matches!(
            fx.key(&server, "a").await,
            Err(ChirpAuthError::JwksFetch(_))
        ));
        // Failures are not cached: the next caller retries and recovers.
        server.set(Response::kids(&["a"]));
        assert!(fx.key(&server, "a").await.is_ok());
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreachable_endpoint_is_a_jwks_fetch_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/jwks.json", listener.local_addr().unwrap());
        drop(listener);
        let fx = Fixture::new();
        assert!(matches!(
            fx.cache.key(&fx.client, &url, "a").await,
            Err(ChirpAuthError::JwksFetch(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_refetch_keeps_serving_known_kids_from_the_fresh_keyset() {
        let server = Server::start(Response::kids(&["a"])).await;
        let fx = Fixture::new();
        fx.key(&server, "a").await.unwrap();
        let mut down = Response::kids(&[]);
        down.status = 503;
        server.set(down);
        fx.set_time(MIN_REFRESH_INTERVAL.as_secs() as i64);
        // The unknown kid needs the upstream, which is down: say so.
        assert!(matches!(
            fx.key(&server, "b").await,
            Err(ChirpAuthError::JwksFetch(_))
        ));
        // A known kid in a still-fresh keyset needs no upstream at all.
        assert!(fx.key(&server, "a").await.is_ok());
        assert_eq!(server.hits(), 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_callers_share_one_failed_attempt() {
        let mut throttled = Response::kids(&["a"]);
        throttled.status = 429;
        throttled.delay = Duration::from_millis(300);
        let server = Server::start(throttled).await;
        let fx = Fixture::new();
        let tasks: Vec<_> = (0..32)
            .map(|_| {
                let (cache, client, url) = (fx.cache.clone(), fx.client.clone(), server.url.clone());
                tokio::spawn(async move { cache.key(&client, &url, "a").await })
            })
            .collect();
        for task in tasks {
            assert!(matches!(
                task.await.unwrap(),
                Err(ChirpAuthError::JwksFetch(_))
            ));
        }
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn cache_control_parsing() {
        let parse = |value: &str| {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::CACHE_CONTROL, value.parse().unwrap());
            cache_control_max_age(&headers)
        };
        assert_eq!(
            parse("public, max-age=300, stale-while-revalidate=600"),
            Some(Duration::from_secs(300))
        );
        assert_eq!(parse("Max-Age = 7"), Some(Duration::from_secs(7)));
        assert_eq!(parse("no-store"), None);
        assert_eq!(parse("max-age=soon"), None);
        assert_eq!(parse("s-maxage=60"), None);
        assert_eq!(cache_control_max_age(&http::HeaderMap::new()), None);
    }
}
