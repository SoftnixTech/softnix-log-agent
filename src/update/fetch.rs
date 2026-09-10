//! A deliberately minimal HTTPS GET client, scoped to exactly one job:
//! fetching a signed update manifest (or the artifact it points at) with a
//! hard size cap. This is not a general-purpose HTTP client — it has no
//! POST, no cookie jar, nothing beyond what Phase 2/3 of the self-update
//! mechanism needs. It DOES follow HTTP redirects (bounded, HTTPS
//! re-enforced on every hop) — GitHub Release asset URLs (the actual
//! artifact host this project's release pipeline uses) always 302 to a
//! signed, time-limited blob storage URL, pinned version or not, so a
//! client that refused to follow redirects could never fetch a real
//! release at all. Confirmed directly against a live release before this
//! was added: an earlier version of this module had no redirect support
//! and the whole networked-apply feature was non-functional against any
//! artifact actually hosted this way.

use anyhow::{bail, Context, Result};
use http_body_util::BodyExt;
use hyper_util::client::legacy::connect::Connect;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Bounds redirect-following against a loop (malicious or misconfigured
/// server) without meaningfully restricting real-world use — GitHub's
/// release-asset hosting, the actual reason this exists, needs exactly one
/// hop.
const MAX_REDIRECTS: u32 = 5;

/// Rejects any URL that isn't `https://`, before any connection is
/// attempted. A security-relevant fetch over plaintext HTTP is never
/// correct here, even if a caller passed one in by misconfiguration.
pub fn require_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("refusing to fetch a non-https URL: {url}");
    }
    Ok(())
}

/// Fetches `url` and returns its body, refusing to read past `max_bytes` —
/// a malicious or broken server sending an unbounded response must not be
/// allowed to exhaust memory on a host that may be running this as
/// root/LocalSystem. Follows up to `MAX_REDIRECTS` HTTP redirects,
/// re-running `validate_url` (the same check the original URL had to pass)
/// against every `Location` target before following it — a redirect is
/// exactly as trusted as the URL a caller handed in, never more, so a
/// malicious or compromised redirect cannot silently downgrade to
/// plaintext HTTP or otherwise bypass whatever `validate_url` enforces.
/// 10s timeout on connect+headers only, per hop — a server that responds
/// promptly then drip-feeds the body slowly can still stall this call
/// indefinitely; the byte cap bounds memory in that case, not time. Callers
/// fetching something large and slow (e.g. a full release artifact) must
/// wrap this in their own outer, whole-operation timeout — `apply.rs`'s
/// `fetch_manifest_and_artifact` already does, for exactly this reason.
///
/// Generic over the connector so tests can exercise this exact function —
/// including the redirect-following logic — against a local plain-HTTP
/// server without needing a real TLS certificate; `fetch_url` below is the
/// real, `https_only()`-enforced entry point every non-test caller uses.
async fn fetch_with_connector<C>(
    connector: C,
    url: &str,
    max_bytes: u64,
    validate_url: impl Fn(&str) -> Result<()>,
) -> Result<Vec<u8>>
where
    C: Connect + Clone + Send + Sync + 'static,
{
    validate_url(url)?;
    let client: Client<_, http_body_util::Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let mut current_url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let uri: hyper::Uri = current_url
            .parse()
            .with_context(|| format!("invalid URL: {current_url}"))?;
        let request = hyper::Request::get(uri)
            .body(http_body_util::Full::new(bytes::Bytes::new()))
            .context("cannot build request")?;

        let response =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.request(request))
                .await
                .context("request timed out after 10s")?
                .context("request failed")?;

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(hyper::header::LOCATION)
                .with_context(|| format!("redirect from {current_url} has no Location header"))?
                .to_str()
                .context("redirect Location header is not valid UTF-8")?
                .to_string();
            // Relative Location values (no scheme) are rejected by
            // `validate_url` itself (both `require_https` and the test
            // module's no-op-but-still-http-only-in-practice callers
            // expect an absolute URL) rather than resolved against
            // `current_url` — every real redirect this function needs to
            // follow (GitHub's release-asset hosting) already sends an
            // absolute URL, so resolving relative ones is unneeded
            // complexity, not a gap.
            validate_url(&location)?;
            current_url = location;
            continue;
        }

        if !response.status().is_success() {
            bail!("fetching {current_url} returned HTTP {}", response.status());
        }

        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.context("error reading response body")?;
            if let Some(chunk) = frame.data_ref() {
                if collected.len() as u64 + chunk.len() as u64 > max_bytes {
                    bail!("response from {current_url} exceeded the {max_bytes}-byte cap");
                }
                collected.extend_from_slice(chunk);
            }
        }
        return Ok(collected);
    }

    bail!("exceeded {MAX_REDIRECTS} redirects fetching {url}")
}

pub async fn fetch_url(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    fetch_with_connector(https, url, max_bytes, require_https).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_https_accepts_an_https_url() {
        assert!(require_https("https://example.invalid/manifest.json").is_ok());
    }

    #[test]
    fn require_https_rejects_plain_http() {
        let err = require_https("http://example.invalid/manifest.json").unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    #[test]
    fn require_https_rejects_a_bare_hostname() {
        let err = require_https("example.invalid/manifest.json").unwrap_err();
        assert!(err.to_string().contains("non-https"));
    }

    // Exercises the size-cap, redirect-following, and success path against
    // a real local HTTP server (not HTTPS — TLS handshake correctness is
    // `hyper-rustls`'s own well-tested job, not this module's; what this
    // module owns is the cap-enforcement, redirect, and body-collection
    // logic, which is identical regardless of the transport).
    // `fetch_with_connector` (the real function `fetch_url` itself calls)
    // is exercised directly here with a plain `HttpConnector` and a no-op
    // validator, so this is the actual production code path under test,
    // not a hand-duplicated copy.
    async fn fetch_url_for_test(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let http = hyper_util::client::legacy::connect::HttpConnector::new();
        fetch_with_connector(http, url, max_bytes, |_| Ok(())).await
    }

    async fn spawn_test_server(body: &'static [u8]) -> String {
        use std::convert::Infallible;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |_req| async move {
                        Ok::<_, Infallible>(hyper::Response::new(http_body_util::Full::new(
                            bytes::Bytes::from_static(body),
                        )))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Serves a `302` from `/redirect` pointing at `/final` on the same
    /// server, and `body` from everything else — mirrors GitHub's own
    /// release-asset hosting shape closely enough to exercise the same
    /// redirect-following path this module added specifically because of
    /// it.
    async fn spawn_redirect_test_server(body: &'static [u8]) -> String {
        use std::convert::Infallible;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| async move {
                            let response = if req.uri().path() == "/redirect" {
                                hyper::Response::builder()
                                    .status(hyper::StatusCode::FOUND)
                                    .header(hyper::header::LOCATION, format!("http://{addr}/final"))
                                    .body(http_body_util::Full::new(bytes::Bytes::new()))
                                    .unwrap()
                            } else {
                                hyper::Response::new(http_body_util::Full::new(
                                    bytes::Bytes::from_static(body),
                                ))
                            };
                            Ok::<_, Infallible>(response)
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    /// Redirects every path back to itself, forever — proves `MAX_REDIRECTS`
    /// actually bounds the loop instead of hanging or recursing unboundedly.
    async fn spawn_infinite_redirect_test_server() -> String {
        use std::convert::Infallible;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let io = hyper_util::rt::TokioIo::new(stream);
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| async move {
                            let response = hyper::Response::builder()
                                .status(hyper::StatusCode::FOUND)
                                .header(
                                    hyper::header::LOCATION,
                                    format!("http://{addr}{}", req.uri().path()),
                                )
                                .body(http_body_util::Full::new(bytes::Bytes::new()))
                                .unwrap();
                            Ok::<_, Infallible>(response)
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_url_follows_a_redirect_to_the_final_content() {
        let base = spawn_redirect_test_server(b"final content").await;
        let body = fetch_url_for_test(&format!("{base}/redirect"), 1024)
            .await
            .unwrap();
        assert_eq!(body, b"final content");
    }

    #[tokio::test]
    async fn fetch_url_gives_up_after_too_many_redirects() {
        let base = spawn_infinite_redirect_test_server().await;
        let err = fetch_url_for_test(&format!("{base}/loop"), 1024)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("redirects"));
    }

    /// The security property that makes redirect-following safe: a
    /// malicious or compromised redirect target is exactly as trusted as
    /// the URL a caller handed in, never more — `validate_url` runs again
    /// on every hop's `Location`, not just the entry URL. Uses a validator
    /// that accepts only the entry path so a redirect to anything else is
    /// provably rejected by that re-check, not by some other failure.
    #[tokio::test]
    async fn fetch_with_connector_re_validates_the_redirect_target_not_just_the_entry_url() {
        let base = spawn_redirect_test_server(b"should never be reached").await;
        let http = hyper_util::client::legacy::connect::HttpConnector::new();
        let err = fetch_with_connector(http, &format!("{base}/redirect"), 1024, |u| {
            if u.ends_with("/redirect") {
                Ok(())
            } else {
                bail!("rejected by test validator: {u}")
            }
        })
        .await
        .unwrap_err();
        assert!(err.to_string().contains("rejected by test validator"));
    }

    #[tokio::test]
    async fn fetch_url_returns_the_full_body_under_the_cap() {
        let base = spawn_test_server(b"hello world").await;
        let body = fetch_url_for_test(&format!("{base}/x"), 1024)
            .await
            .unwrap();
        assert_eq!(body, b"hello world");
    }

    #[tokio::test]
    async fn fetch_url_rejects_a_body_over_the_cap() {
        let base = spawn_test_server(b"hello world").await;
        let err = fetch_url_for_test(&format!("{base}/x"), 5)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("cap"));
    }
}
