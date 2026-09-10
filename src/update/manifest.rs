//! Signed update manifest: format, and the only code path allowed to trust
//! a downloaded/staged release artifact.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Ed25519 public keys this build trusts. Empty on purpose until Phase 0's
/// release-engineering runbook generates the real signing key — a build
/// with no trusted keys must refuse to verify anything (see
/// `verify_manifest`), never silently accept.
pub const RELEASE_PUBLIC_KEYS: &[[u8; 32]] = &[];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub manifest_serial: u64,
    pub released_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub min_upgrade_from: Option<String>,
    pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Artifact {
    pub platform: String,
    pub arch: String,
    pub filename: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// Verifies `sig` (a detached Ed25519 signature) over the exact bytes of
/// `bytes`, against every key in `RELEASE_PUBLIC_KEYS`, then parses and
/// sanity-checks the manifest. Never trust a manifest that hasn't been
/// through this function.
///
/// Thin wrapper around `verify_manifest_with_keys` so tests can exercise
/// the real verification body against a real test keypair instead of the
/// (intentionally empty until the Phase 0 signing-key runbook runs)
/// `RELEASE_PUBLIC_KEYS` — see that function and the `tests` module below.
pub fn verify_manifest(bytes: &[u8], sig: &[u8]) -> Result<Manifest> {
    verify_manifest_with_keys(bytes, sig, RELEASE_PUBLIC_KEYS)
}

/// The actual signature/schema/product verification logic, parameterized
/// over the trusted-key list. `verify_manifest` is the only non-test
/// caller, and always passes `RELEASE_PUBLIC_KEYS` — this split exists
/// purely so `#[cfg(test)]` code below can call this directly with a real
/// generated-for-tests keypair, exercising the exact same code every real
/// caller runs instead of re-implementing/bypassing it (as every prior test
/// in this module did, by either relying on `RELEASE_PUBLIC_KEYS` staying
/// empty, or calling `ring`'s verify directly).
fn verify_manifest_with_keys(bytes: &[u8], sig: &[u8], keys: &[[u8; 32]]) -> Result<Manifest> {
    if keys.is_empty() {
        bail!("no release public keys compiled into this build; refusing to verify any manifest");
    }
    let verified = keys.iter().any(|pk| {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk)
            .verify(bytes, sig)
            .is_ok()
    });
    if !verified {
        bail!("manifest signature does not verify against any trusted release key");
    }
    let manifest: Manifest = serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
    if manifest.schema_version != 1 {
        bail!(
            "unsupported manifest schema_version {} (this build understands schema_version 1)",
            manifest.schema_version
        );
    }
    if manifest.product != "softnix-log-agent" {
        bail!(
            "manifest is for product {:?}, not softnix-log-agent",
            manifest.product
        );
    }
    Ok(manifest)
}

pub(crate) fn parse_version(v: &str) -> Result<(u64, u64, u64)> {
    let mut parts = v.trim().splitn(3, '.');
    let major = parts
        .next()
        .context("empty version string")?
        .parse()
        .with_context(|| format!("invalid major version in {v:?}"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse()
        .with_context(|| format!("invalid minor version in {v:?}"))?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse()
        .with_context(|| format!("invalid patch version in {v:?}"))?;
    Ok((major, minor, patch))
}

/// Rejects a manifest that is a replay (serial not strictly newer than the
/// last one this host accepted), expired, or a downgrade — unless the
/// downgrade is explicitly requested. Called after `verify_manifest`, never
/// before: signature validity says nothing about freshness.
pub fn check_freshness(
    manifest: &Manifest,
    highest_seen_serial: u64,
    running_version: &str,
    allow_downgrade: bool,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if manifest.manifest_serial <= highest_seen_serial {
        bail!(
            "manifest_serial {} is not newer than the last accepted serial {} (possible replay)",
            manifest.manifest_serial,
            highest_seen_serial
        );
    }
    let expires_at: chrono::DateTime<chrono::Utc> =
        manifest.expires_at.parse().with_context(|| {
            format!(
                "manifest expires_at {:?} is not RFC3339",
                manifest.expires_at
            )
        })?;
    if now > expires_at {
        bail!("manifest expired at {}", manifest.expires_at);
    }
    let target = parse_version(&manifest.version)?;
    let running = parse_version(running_version)?;
    if !allow_downgrade && target < running {
        bail!(
            "manifest version {} is older than the running version {} (pass --allow-downgrade to force)",
            manifest.version,
            running_version
        );
    }
    if let Some(min_from) = &manifest.min_upgrade_from {
        let min_from_parsed = parse_version(min_from)?;
        if running < min_from_parsed {
            bail!(
                "this release requires upgrading from at least {} first (min_upgrade_from); running version is {}",
                min_from,
                running_version
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    // A real Ed25519 keypair generated once for tests only (not a release
    // key). Generated with:
    //   openssl genpkey -algorithm ed25519 -out /tmp/test-key.pem
    //   openssl pkey -in /tmp/test-key.pem -pubout -outform DER -out /tmp/test-pub.der
    //   openssl pkey -in /tmp/test-key.pem -outform DER -out /tmp/test-priv.der
    // then the last 32 bytes of test-pub.der are the raw public key, and
    // `ring::signature::Ed25519KeyPair::from_pkcs8` loads test-priv.der
    // directly (it's already PKCS8) for signing in these tests.
    fn test_keypair() -> (ring::signature::Ed25519KeyPair, [u8; 32]) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(keypair.public_key().as_ref());
        (keypair, pubkey)
    }

    fn sample_manifest_bytes() -> Vec<u8> {
        serde_json::to_vec(&Manifest {
            schema_version: 1,
            product: "softnix-log-agent".into(),
            version: "0.2.0".into(),
            manifest_serial: 1,
            released_at: "2026-09-09T00:00:00Z".into(),
            expires_at: "2027-09-09T00:00:00Z".into(),
            min_upgrade_from: None,
            artifacts: vec![],
        })
        .unwrap()
    }

    #[test]
    fn accepts_a_correctly_signed_manifest() {
        let (keypair, pubkey) = test_keypair();
        let bytes = sample_manifest_bytes();
        let sig = keypair.sign(&bytes);

        // Exercises the real body every caller runs (`verify_manifest_with_keys`,
        // which `verify_manifest` is a thin wrapper around), against a real
        // test keypair — not `RELEASE_PUBLIC_KEYS`, which stays empty until
        // the Phase 0 signing-key runbook runs, and not a bypass straight to
        // `ring`'s verify.
        let manifest = verify_manifest_with_keys(&bytes, sig.as_ref(), &[pubkey]).unwrap();
        assert_eq!(manifest.version, "0.2.0");
    }

    #[test]
    fn rejects_a_tampered_manifest() {
        let (keypair, pubkey) = test_keypair();
        let mut bytes = sample_manifest_bytes();
        let sig = keypair.sign(&bytes);
        bytes.push(b' '); // tamper after signing

        let err = verify_manifest_with_keys(&bytes, sig.as_ref(), &[pubkey]).unwrap_err();
        assert!(err.to_string().contains("does not verify"));
    }

    #[test]
    fn rejects_signature_from_the_wrong_key() {
        let (keypair, _pubkey) = test_keypair();
        let (_other_keypair, other_pubkey) = test_keypair();
        let bytes = sample_manifest_bytes();
        let sig = keypair.sign(&bytes);

        let err = verify_manifest_with_keys(&bytes, sig.as_ref(), &[other_pubkey]).unwrap_err();
        assert!(err.to_string().contains("does not verify"));
    }

    #[test]
    fn verify_manifest_refuses_everything_when_no_keys_are_trusted() {
        // RELEASE_PUBLIC_KEYS is empty in this build (Phase 0 runbook not
        // yet run) — the public `verify_manifest` (which always uses
        // `RELEASE_PUBLIC_KEYS`) must fail closed, not open.
        let bytes = sample_manifest_bytes();
        let err = verify_manifest(&bytes, &[0u8; 64]).unwrap_err();
        assert!(err.to_string().contains("no release public keys"));
    }

    #[test]
    fn verify_manifest_with_keys_rejects_wrong_schema_version() {
        let (keypair, pubkey) = test_keypair();
        let mut m: serde_json::Value = serde_json::from_slice(&sample_manifest_bytes()).unwrap();
        m["schema_version"] = serde_json::Value::from(2);
        let bytes = serde_json::to_vec(&m).unwrap();
        let sig = keypair.sign(&bytes);

        let err = verify_manifest_with_keys(&bytes, sig.as_ref(), &[pubkey]).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported manifest schema_version"));
    }

    #[test]
    fn verify_manifest_with_keys_rejects_wrong_product() {
        let (keypair, pubkey) = test_keypair();
        let mut m: serde_json::Value = serde_json::from_slice(&sample_manifest_bytes()).unwrap();
        m["product"] = serde_json::Value::String("some-other-agent".into());
        let bytes = serde_json::to_vec(&m).unwrap();
        let sig = keypair.sign(&bytes);

        // A correctly-signed manifest for the wrong product must still be
        // rejected — signature validity says nothing about which product
        // the manifest claims to be for.
        let err = verify_manifest_with_keys(&bytes, sig.as_ref(), &[pubkey]).unwrap_err();
        assert!(err.to_string().contains("not softnix-log-agent"));
    }

    fn manifest_with(serial: u64, version: &str, expires_at: &str) -> Manifest {
        Manifest {
            schema_version: 1,
            product: "softnix-log-agent".into(),
            version: version.into(),
            manifest_serial: serial,
            released_at: "2026-09-09T00:00:00Z".into(),
            expires_at: expires_at.into(),
            min_upgrade_from: None,
            artifacts: vec![],
        }
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        "2026-09-09T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn accepts_a_newer_serial_and_newer_version() {
        let m = manifest_with(2, "0.2.0", "2027-01-01T00:00:00Z");
        assert!(check_freshness(&m, 1, "0.1.5", false, now()).is_ok());
    }

    #[test]
    fn rejects_a_serial_that_is_not_strictly_newer() {
        let m = manifest_with(1, "0.2.0", "2027-01-01T00:00:00Z");
        let err = check_freshness(&m, 1, "0.1.5", false, now()).unwrap_err();
        assert!(err.to_string().contains("not newer"));
    }

    #[test]
    fn rejects_an_expired_manifest() {
        let m = manifest_with(2, "0.2.0", "2026-01-01T00:00:00Z");
        let err = check_freshness(&m, 1, "0.1.5", false, now()).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn rejects_a_downgrade_without_the_flag() {
        let m = manifest_with(2, "0.1.0", "2027-01-01T00:00:00Z");
        let err = check_freshness(&m, 1, "0.1.5", false, now()).unwrap_err();
        assert!(err.to_string().contains("downgrade"));
    }

    #[test]
    fn allows_a_downgrade_with_the_flag() {
        let m = manifest_with(2, "0.1.0", "2027-01-01T00:00:00Z");
        assert!(check_freshness(&m, 1, "0.1.5", true, now()).is_ok());
    }

    #[test]
    fn rejects_skipping_below_min_upgrade_from() {
        let mut m = manifest_with(2, "0.3.0", "2027-01-01T00:00:00Z");
        m.min_upgrade_from = Some("0.2.0".into());
        let err = check_freshness(&m, 1, "0.1.5", false, now()).unwrap_err();
        assert!(err.to_string().contains("min_upgrade_from"));
    }
}
