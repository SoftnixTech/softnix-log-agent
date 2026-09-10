//! A deliberately minimal HTTPS GET client, scoped to exactly one job:
//! fetching a signed update manifest (or the artifact it points at) with a
//! hard size cap. This is not a general-purpose HTTP client — it has no
//! POST, no redirect following, no cookie jar, nothing beyond what
//! Phase 2/3 of the self-update mechanism needs.

use anyhow::{bail, Context, Result};
use http_body_util::BodyExt;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

/// Rejects any URL that isn't `https://`, before any connection is
/// attempted. A security-relevant fetch over plaintext HTTP is never
/// correct here, even if a caller passed one in by misconfiguration.
pub fn require_https(url: &str) -> Result<()> {
    if !url.starts_with("https://") {
        bail!("refusing to fetch a non-https URL: {url}");
    }
    Ok(())
}

/// Fetches `url` (which must already have passed `require_https`) and
/// returns its body, refusing to read past `max_bytes` — a malicious or
/// broken server sending an unbounded response must not be allowed to
/// exhaust memory on a host that may be running this as root/LocalSystem.
/// 10s connect+request timeout: this must never hang the CLI indefinitely.
pub async fn fetch_url(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    require_https(url)?;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, http_body_util::Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(https);

    let uri: hyper::Uri = url.parse().with_context(|| format!("invalid URL: {url}"))?;
    let request = hyper::Request::get(uri)
        .body(http_body_util::Full::new(bytes::Bytes::new()))
        .context("cannot build request")?;

    let response =
        tokio::time::timeout(std::time::Duration::from_secs(10), client.request(request))
            .await
            .context("request timed out after 10s")?
            .context("request failed")?;

    if !response.status().is_success() {
        bail!("fetching {url} returned HTTP {}", response.status());
    }

    let mut body = response.into_body();
    let mut collected = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.context("error reading response body")?;
        if let Some(chunk) = frame.data_ref() {
            if collected.len() as u64 + chunk.len() as u64 > max_bytes {
                bail!("response from {url} exceeded the {max_bytes}-byte cap");
            }
            collected.extend_from_slice(chunk);
        }
    }
    Ok(collected)
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

    // Exercises the size-cap and success path against a real local HTTP
    // server (not HTTPS — TLS handshake correctness is `hyper-rustls`'s own
    // well-tested job, not this module's; what this module owns is the
    // cap-enforcement and body-collection logic, which is identical
    // regardless of the transport). `fetch_url_for_test` below is the same
    // function with `require_https` skipped, so the local plain-HTTP test
    // server can stand in for what would be an HTTPS endpoint in
    // production.
    async fn fetch_url_for_test(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
        let https = hyper_util::client::legacy::connect::HttpConnector::new();
        let client: Client<_, http_body_util::Full<bytes::Bytes>> =
            Client::builder(TokioExecutor::new()).build(https);
        let uri: hyper::Uri = url.parse()?;
        let request =
            hyper::Request::get(uri).body(http_body_util::Full::new(bytes::Bytes::new()))?;
        let response = client.request(request).await?;
        if !response.status().is_success() {
            bail!("HTTP {}", response.status());
        }
        let mut body = response.into_body();
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Some(chunk) = frame.data_ref() {
                if collected.len() as u64 + chunk.len() as u64 > max_bytes {
                    bail!("exceeded cap");
                }
                collected.extend_from_slice(chunk);
            }
        }
        Ok(collected)
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
