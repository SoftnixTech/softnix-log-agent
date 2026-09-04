//! TLS helpers for syslog listeners (server) and outputs (client), with mTLS.

use crate::config::{TlsClientOptions, TlsServerOptions};
use anyhow::{anyhow, Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

pub fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut rd = BufReader::new(
        File::open(path).with_context(|| format!("cannot open certificate {}", path.display()))?,
    );
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("invalid PEM in {}", path.display()))?;
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut rd = BufReader::new(
        File::open(path).with_context(|| format!("cannot open private key {}", path.display()))?,
    );
    rustls_pemfile::private_key(&mut rd)
        .with_context(|| format!("invalid PEM in {}", path.display()))?
        .ok_or_else(|| anyhow!("no private key found in {}", path.display()))
}

/// Server-side TLS config for syslog TLS listeners; enables mTLS when a
/// client CA is configured.
pub fn server_config(opts: &TlsServerOptions) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(&opts.cert)?;
    let key = load_key(&opts.key)?;
    let builder = rustls::ServerConfig::builder();
    let cfg = if let Some(ca) = &opts.client_ca {
        let mut roots = rustls::RootCertStore::empty();
        for c in load_certs(ca)? {
            roots.add(c).context("invalid CA certificate")?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .context("cannot build client certificate verifier")?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        builder.with_no_client_auth().with_single_cert(certs, key)?
    };
    Ok(Arc::new(cfg))
}

/// Client-side TLS config for TLS outputs; supports custom CA, mTLS, and
/// (discouraged, explicit) verification bypass.
pub fn client_config(opts: &TlsClientOptions) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(ca) = &opts.ca {
        for c in load_certs(ca)? {
            roots.add(c).context("invalid CA certificate")?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut cfg = match (&opts.cert, &opts.key) {
        (Some(c), Some(k)) => builder.with_client_auth_cert(load_certs(c)?, load_key(k)?)?,
        _ => builder.with_no_client_auth(),
    };
    if !opts.verify {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(NoVerify::new()));
    }
    Ok(Arc::new(cfg))
}

/// Certificate verifier that accepts anything. Only used when the operator
/// explicitly sets `tls.verify: false`; a warning is emitted at startup.
#[derive(Debug)]
struct NoVerify(rustls::crypto::CryptoProvider);

impl NoVerify {
    fn new() -> Self {
        NoVerify(rustls::crypto::ring::default_provider())
    }
}

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
