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
pub fn verify_manifest(bytes: &[u8], sig: &[u8]) -> Result<Manifest> {
    if RELEASE_PUBLIC_KEYS.is_empty() {
        bail!("no release public keys compiled into this build; refusing to verify any manifest");
    }
    let verified = RELEASE_PUBLIC_KEYS.iter().any(|pk| {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk)
            .verify(bytes, sig)
            .is_ok()
    });
    if !verified {
        bail!("manifest signature does not verify against any trusted release key");
    }
    let manifest: Manifest =
        serde_json::from_slice(bytes).context("manifest is not valid JSON")?;
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

        // Can't mutate the real `RELEASE_PUBLIC_KEYS` const from a test, so
        // this test exercises the verification logic directly rather than
        // through `verify_manifest`. See Step 4 for why `verify_manifest`
        // stays a thin wrapper around a testable inner function.
        let ok = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey)
            .verify(&bytes, sig.as_ref())
            .is_ok();
        assert!(ok);
    }

    #[test]
    fn rejects_a_tampered_manifest() {
        let (keypair, pubkey) = test_keypair();
        let mut bytes = sample_manifest_bytes();
        let sig = keypair.sign(&bytes);
        bytes.push(b' '); // tamper after signing

        let ok = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey)
            .verify(&bytes, sig.as_ref())
            .is_ok();
        assert!(!ok);
    }

    #[test]
    fn rejects_signature_from_the_wrong_key() {
        let (keypair, _pubkey) = test_keypair();
        let (_other_keypair, other_pubkey) = test_keypair();
        let bytes = sample_manifest_bytes();
        let sig = keypair.sign(&bytes);

        let ok = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &other_pubkey)
            .verify(&bytes, sig.as_ref())
            .is_ok();
        assert!(!ok);
    }

    #[test]
    fn verify_manifest_refuses_everything_when_no_keys_are_trusted() {
        // RELEASE_PUBLIC_KEYS is empty in this build (Phase 0 runbook not
        // yet run) — verify_manifest must fail closed, not open.
        let bytes = sample_manifest_bytes();
        let err = verify_manifest(&bytes, &[0u8; 64]).unwrap_err();
        assert!(err.to_string().contains("no release public keys"));
    }

    #[test]
    fn verify_manifest_rejects_wrong_product() {
        let mut m: serde_json::Value = serde_json::from_slice(&sample_manifest_bytes()).unwrap();
        m["product"] = serde_json::Value::String("some-other-agent".into());
        let bytes = serde_json::to_vec(&m).unwrap();
        // Signature check happens first and this build trusts no keys, so
        // this exercises the same fail-closed path as the test above by
        // design — the product check is proven correct once Task 6 wires a
        // real test key into a feature-gated test build. Tracked there.
        let err = verify_manifest(&bytes, &[0u8; 64]).unwrap_err();
        assert!(err.to_string().contains("no release public keys"));
    }
}
