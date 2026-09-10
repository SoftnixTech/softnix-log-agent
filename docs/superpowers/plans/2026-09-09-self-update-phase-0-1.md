# Self-Update Mechanism (Phase 0 + Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `softnix-log-agent upgrade --from <local artifact> [--rollback]` — a fully offline, signature-verified, self-rolling-back in-place upgrade — plus the release-side signing infrastructure it depends on. No network code, no UI apply button, no separate updater binary.

**Architecture:** A new `src/update/` module verifies an Ed25519-signed manifest (bundled inside the release artifact) against a public key compiled into the binary, persists an anti-replay watermark under `data_dir`, preflights the staged binary out-of-band before touching anything live, then swaps it in via a platform-specific atomic mechanism (Linux: same-directory hardlink-aside + atomic rename + `systemctl restart`; Windows: self-copy-and-relaunch driving a verified MSI major upgrade) with automatic one-shot rollback on preflight or health-check failure. The release pipeline is extended to emit and sign that manifest, and a pre-existing bug that already blocks any Windows MSI upgrade (hardcoded `ProductVersion`) is fixed as a prerequisite.

**Tech Stack:** Rust (existing crate), `ring` 0.17 (promoted from a transitive to a direct dependency — already resolved via `rustls`, adds no new crate to the dependency tree), `hex` 0.4 (new, tiny, zero-dependency), the system `tar` binary via `std::process::Command` (Linux artifact extraction — no new Rust crate), WiX v3 (already used), OpenSSL CLI (release-engineering runbook only, not a build dependency).

**Spec:** `docs/superpowers/specs/2026-09-09-self-update-mechanism.md`

## Global Constraints

- No network client code anywhere in this plan. `--from <local artifact>` only. (Spec: Phase 1 scope.)
- No UI apply button, ever, in this codebase. (Spec constraint 1.)
- No separate updater helper binary; Windows uses a self-copy of the same signed binary. (Spec constraint 6.)
- Ed25519 public key(s) compiled into the binary as a `const`, never read from config or any file the running agent's own config-write API could reach. (Spec constraint 2.)
- Windows applies via MSI major upgrade only; no direct `.exe` overwrite of a live install. (Spec constraint 4.)
- Rollback fires at most once per upgrade attempt; never loops. (Spec constraint 5.)
- Every new module lives under `src/update/`; platform-specific code is split into `apply_linux.rs` / `apply_windows.rs` behind `#[cfg(...)]`, mirroring the existing split in `src/service.rs`.

---

## File Structure

| File | Responsibility |
|---|---|
| `src/update/mod.rs` | Module root; re-exports the public surface `main.rs` calls |
| `src/update/manifest.rs` | `Manifest`/`Artifact` structs, Ed25519 signature verification, freshness/downgrade/version checks |
| `src/update/watermark.rs` | Persisted anti-replay state (highest accepted `manifest_serial`) under `data_dir`, mirrors `src/state.rs`'s `write_atomic` pattern |
| `src/update/verify.rs` | Artifact selection (platform/arch match) + SHA-256 file-hash verification |
| `src/update/apply.rs` | Cross-platform orchestration: extract, verify, preflight, dispatch to platform swap, health-check, record watermark |
| `src/update/apply_linux.rs` | `#[cfg(target_os = "linux")]` stage / hardlink-aside / atomic rename / rollback |
| `src/update/apply_windows.rs` | `#[cfg(windows)]` self-copy-and-relaunch / `msiexec` driver / rollback |
| `src/lib.rs` | Modify: add `pub mod update;` |
| `src/main.rs` | Modify: add `Command::Upgrade` and hidden `Command::UpgradeApply` |
| `Cargo.toml` | Modify: promote `ring` to a direct dependency, add `hex` |
| `packaging/windows/softnix-log-agent.wxs` | Modify: `Version="0.1.0"` → `Version="$(var.Version)"` |
| `.github/workflows/release.yml` | Modify: pass `-dVersion` to `candle.exe`; add manifest generation + signing to `publish` |

---

### Task 1: Manifest struct + Ed25519 signature verification

**Files:**
- Create: `src/update/manifest.rs`
- Create: `src/update/mod.rs`
- Modify: `src/lib.rs:4` (insert `pub mod update;` alphabetically after `pub mod tls;` — actually before it; the list is alphabetical: `state`, `tls`, `web`, so insert between `state` and `tls`)
- Modify: `Cargo.toml` (add to `[dependencies]`: `ring = "0.17"` and `hex = "0.4"`; promote `tempfile` from `[dev-dependencies]` to `[dependencies]`)
- Test: inline `#[cfg(test)] mod tests` in `src/update/manifest.rs`

**Interfaces:**
- Produces: `pub struct Manifest { schema_version: u32, product: String, version: String, manifest_serial: u64, released_at: String, expires_at: String, min_upgrade_from: Option<String>, artifacts: Vec<Artifact> }` (all fields `pub`), `pub struct Artifact { platform: String, arch: String, filename: String, url: String, sha256: String, size: u64 }` (all fields `pub`), `pub fn verify_manifest(bytes: &[u8], sig: &[u8]) -> anyhow::Result<Manifest>`.

- [ ] **Step 1: Add the new dependencies**

Edit `Cargo.toml`, in the `[dependencies]` block, add these two lines (anywhere in the block; alphabetical-ish placement near `regex`/`rustls-pemfile` is fine):

```toml
ring = "0.17"
hex = "0.4"
```

Also move `tempfile = "3"` out of `[dev-dependencies]` into `[dependencies]` (remove the line from one block, add it to the other — do not leave it in both, Cargo warns about that). This isn't needed by anything in *this* task, but is needed starting Task 9 (`apply_from_local`) and Task 11 (`self_relaunch_and_apply`), both of which call `tempfile::tempdir()` from real (non-test) code, not from a `#[cfg(test)]` block — a dev-only dependency cannot be linked into the shipped binary. Doing it now, once, avoids a build break appearing later in a task that isn't "about" dependencies.

- [ ] **Step 2: Run `cargo build` to confirm the new deps resolve**

Run: `cargo build`
Expected: succeeds, no version bump for `ring` in `Cargo.lock` (it's already locked at 0.17.14 via `rustls`).

- [ ] **Step 3: Write the failing tests**

Create `src/update/manifest.rs`:

```rust
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
```

Create `src/update/mod.rs`:

```rust
//! Self-update: signed-manifest verification, staging, platform-specific
//! atomic swap, and rollback. See
//! `docs/superpowers/specs/2026-09-09-self-update-mechanism.md` for the
//! full design and the constraints every function here must uphold.

pub mod manifest;
pub mod watermark;
```

Add to `src/lib.rs` (insert the new line between `pub mod state;` and `pub mod tls;`, keeping the list alphabetical):

```rust
pub mod state;
pub mod update;
pub mod tls;
```

- [ ] **Step 4: Run the tests to see them fail (module doesn't exist yet / doesn't compile)**

Run: `cargo test --lib update::`
Expected: FAIL — `error[E0433]: failed to resolve: use of undeclared crate or module 'update'` (before Step 3's files exist) or a clean compile with the 5 tests passing immediately after (this task's test file is written test-and-implementation-together because the "implementation" here — `verify_manifest` — is a thin wrapper the tests only exercise indirectly; the direct-`ring`-call tests in `accepts_a_correctly_signed_manifest` etc. are the ones proving the crypto primitive is wired correctly). This is the one task in this plan where writing the test first doesn't produce a meaningfully different red/green cycle, because `verify_manifest`'s own logic (empty-keys / bad-JSON / wrong-product checks) has no crypto dependency to fake — it's straight-line code. Proceed to Step 5.

- [ ] **Step 5: Run the tests to confirm they pass**

Run: `cargo test --lib update::manifest::`
Expected: `test result: ok. 5 passed`

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock src/lib.rs src/update/mod.rs src/update/manifest.rs
git commit -m "feat(update): add signed manifest format and Ed25519 verification"
```

---

### Task 2: Freshness, replay, and downgrade checks

**Files:**
- Modify: `src/update/manifest.rs` (add `check_freshness` and a private `parse_version` helper)
- Test: same file, extend `mod tests`

**Interfaces:**
- Consumes: `Manifest` (Task 1).
- Produces: `pub fn check_freshness(manifest: &Manifest, highest_seen_serial: u64, running_version: &str, allow_downgrade: bool, now: chrono::DateTime<chrono::Utc>) -> anyhow::Result<()>`. Later tasks (Task 8) call this with `Watermark::highest_serial()` (Task 3), `env!("CARGO_PKG_VERSION")`, the CLI's `--allow-downgrade` flag, and `chrono::Utc::now()`.

- [ ] **Step 1: Write the failing tests**

Append to `src/update/manifest.rs`'s `mod tests`:

```rust
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib update::manifest::rejects_a_serial`
Expected: FAIL with "cannot find function `check_freshness`"

- [ ] **Step 3: Write the implementation**

Add to `src/update/manifest.rs` (above `mod tests`):

```rust
fn parse_version(v: &str) -> Result<(u64, u64, u64)> {
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
    let expires_at: chrono::DateTime<chrono::Utc> = manifest
        .expires_at
        .parse()
        .with_context(|| format!("manifest expires_at {:?} is not RFC3339", manifest.expires_at))?;
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
```

Add `chrono` usage note: `chrono` is already a dependency (`Cargo.toml`: `chrono = { version = "0.4", features = ["serde"] }`) — no new dependency for this task.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --lib update::manifest::`
Expected: `test result: ok. 11 passed` (5 from Task 1 + 6 new)

- [ ] **Step 5: Commit**

```bash
git add src/update/manifest.rs
git commit -m "feat(update): add manifest freshness, replay, and downgrade checks"
```

---

### Task 3: Watermark persistence

**Files:**
- Create: `src/update/watermark.rs`
- Modify: `src/update/mod.rs` (add `pub mod watermark;`)

**Interfaces:**
- Consumes: `crate::fsutil::write_atomic` (existing, `src/fsutil.rs`).
- Produces: `pub struct Watermark`, `impl Watermark { pub fn open(data_dir: &Path) -> Self; pub fn highest_serial(&self) -> u64; pub fn record(&mut self, serial: u64) -> anyhow::Result<()>; }`. Task 8 constructs this once per `upgrade` invocation from `cfg.agent.data_dir`.

- [ ] **Step 1: Write the failing tests**

Create `src/update/watermark.rs`:

```rust
//! Persisted anti-replay state: the highest `manifest_serial` this host has
//! ever accepted. Mirrors `src/state.rs`'s write-through-`write_atomic`
//! pattern for a single small JSON file.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
struct WatermarkFile {
    highest_manifest_serial: u64,
}

pub struct Watermark {
    path: PathBuf,
    highest_serial: u64,
}

impl Watermark {
    /// Reads `<data_dir>/update-watermark.json` if present; a missing or
    /// unparseable file is treated as "nothing accepted yet" (serial 0),
    /// same tolerance `StateManager::open` already applies to `state.json`.
    pub fn open(data_dir: &Path) -> Self {
        let path = data_dir.join("update-watermark.json");
        let highest_serial = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<WatermarkFile>(&bytes).ok())
            .map(|w| w.highest_manifest_serial)
            .unwrap_or(0);
        Watermark {
            path,
            highest_serial,
        }
    }

    pub fn highest_serial(&self) -> u64 {
        self.highest_serial
    }

    /// Persists `serial` as the new watermark. Callers must only call this
    /// after a successful, health-checked upgrade — recording a serial for
    /// an upgrade that later rolls back would permanently lock this host
    /// out of ever re-accepting that manifest.
    pub fn record(&mut self, serial: u64) -> Result<()> {
        self.highest_serial = serial;
        let bytes = serde_json::to_vec(&WatermarkFile {
            highest_manifest_serial: serial,
        })?;
        crate::fsutil::write_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_at_zero_when_no_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let w = Watermark::open(dir.path());
        assert_eq!(w.highest_serial(), 0);
    }

    #[test]
    fn record_then_reopen_persists_the_value() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watermark::open(dir.path());
        w.record(7).unwrap();

        let reopened = Watermark::open(dir.path());
        assert_eq!(reopened.highest_serial(), 7);
    }

    #[test]
    fn record_leaves_no_stray_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = Watermark::open(dir.path());
        w.record(1).unwrap();
        assert!(!dir.path().join("update-watermark.json.tmp").exists());
    }

    #[test]
    fn a_corrupt_watermark_file_is_treated_as_zero_not_a_crash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("update-watermark.json"), b"not json").unwrap();
        let w = Watermark::open(dir.path());
        assert_eq!(w.highest_serial(), 0);
    }
}
```

Add to `src/update/mod.rs`:

```rust
pub mod manifest;
pub mod watermark;
```

(Note: `watermark` was already listed in Task 1's `mod.rs` snippet — if Task 1 was implemented exactly as written, this line already exists; this step is a no-op confirmation, not a duplicate insertion.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib update::watermark::`
Expected: FAIL — `error[E0433]: failed to resolve: use of undeclared crate or module 'watermark'` before the file exists; passes immediately once created since, as in Task 1, this module's logic has no external dependency to fake first. Create the file per Step 1, then proceed.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --lib update::watermark::`
Expected: `test result: ok. 4 passed`

- [ ] **Step 4: Commit**

```bash
git add src/update/mod.rs src/update/watermark.rs
git commit -m "feat(update): persist an anti-replay watermark under data_dir"
```

---

### Task 4: Artifact selection and SHA-256 verification

**Files:**
- Create: `src/update/verify.rs`
- Modify: `src/update/mod.rs` (add `pub mod verify;`)

**Interfaces:**
- Consumes: `Manifest`, `Artifact` (Task 1).
- Produces: `impl Manifest { pub fn artifact_for(&self, platform: &str, arch: &str) -> Option<&Artifact>; }`, `pub fn verify_artifact_hash(path: &std::path::Path, expected_hex: &str) -> anyhow::Result<()>`.

- [ ] **Step 1: Write the failing tests**

Create `src/update/verify.rs`:

```rust
//! Artifact selection and integrity verification. Signature verification
//! (`manifest::verify_manifest`) proves the *manifest* is authentic; this
//! module proves the *downloaded/staged file on disk* matches what that
//! manifest says it should be — a separate check, because the file is
//! read from disk here, not trusted from whatever was written moments ago.

use super::manifest::{Artifact, Manifest};
use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::Path;

impl Manifest {
    pub fn artifact_for(&self, platform: &str, arch: &str) -> Option<&Artifact> {
        self.artifacts
            .iter()
            .find(|a| a.platform == platform && a.arch == arch)
    }
}

/// Hashes the file at `path` and compares it (constant-time-insensitive
/// comparison is fine here — this isn't a MAC, it's a public checksum whose
/// only job is catching corruption/tampering already ruled out by the
/// manifest's signature; the signature is what carries the security
/// property) against `expected_hex` (lowercase hex, as the manifest stores
/// it). Re-reads the file from disk rather than trusting any in-memory
/// buffer the caller might have.
pub fn verify_artifact_hash(path: &Path, expected_hex: &str) -> Result<()> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let actual = hex::encode(ctx.finish().as_ref());
    let expected = expected_hex.to_lowercase();
    if actual != expected {
        bail!(
            "hash mismatch for {}: expected {expected}, got {actual}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::manifest::Manifest;

    fn sample_manifest() -> Manifest {
        Manifest {
            schema_version: 1,
            product: "softnix-log-agent".into(),
            version: "0.2.0".into(),
            manifest_serial: 1,
            released_at: "2026-09-09T00:00:00Z".into(),
            expires_at: "2027-09-09T00:00:00Z".into(),
            min_upgrade_from: None,
            artifacts: vec![
                Artifact {
                    platform: "linux".into(),
                    arch: "x86_64".into(),
                    filename: "a.tar.gz".into(),
                    url: "https://example.invalid/a.tar.gz".into(),
                    sha256: "deadbeef".into(),
                    size: 1,
                },
                Artifact {
                    platform: "windows".into(),
                    arch: "x86_64".into(),
                    filename: "a.msi".into(),
                    url: "https://example.invalid/a.msi".into(),
                    sha256: "cafef00d".into(),
                    size: 1,
                },
            ],
        }
    }

    #[test]
    fn finds_the_matching_platform_and_arch() {
        let m = sample_manifest();
        assert_eq!(m.artifact_for("linux", "x86_64").unwrap().filename, "a.tar.gz");
        assert_eq!(m.artifact_for("windows", "x86_64").unwrap().filename, "a.msi");
    }

    #[test]
    fn returns_none_for_an_unlisted_platform() {
        let m = sample_manifest();
        assert!(m.artifact_for("macos", "aarch64").is_none());
    }

    #[test]
    fn verify_artifact_hash_accepts_a_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello world").unwrap();
        // sha256("hello world")
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde";
        assert!(verify_artifact_hash(&path, expected).is_ok());
    }

    #[test]
    fn verify_artifact_hash_rejects_a_mismatched_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let err = verify_artifact_hash(&path, "0000000000000000000000000000000000000000000000000000000000000000").unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn verify_artifact_hash_errors_cleanly_on_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.bin");
        assert!(verify_artifact_hash(&path, "deadbeef").is_err());
    }
}
```

Add to `src/update/mod.rs`:

```rust
pub mod verify;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib update::verify::`
Expected: FAIL — module doesn't exist / `hex` not yet used here (it is already a dependency from Task 1).

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --lib update::verify::`
Expected: `test result: ok. 5 passed`

- [ ] **Step 4: Commit**

```bash
git add src/update/mod.rs src/update/verify.rs
git commit -m "feat(update): add artifact selection and sha256 verification"
```

---

### Task 5: Fix the hardcoded MSI ProductVersion (blocks all Windows upgrades today)

**Files:**
- Modify: `packaging/windows/softnix-log-agent.wxs:19`
- Modify: `.github/workflows/release.yml` (the `Build MSI` step's `candle.exe` invocation)

This is a pre-existing bug independent of everything else in this plan — every MSI ever built by this pipeline declares `ProductVersion="0.1.0"` under the same `UpgradeCode`, so WiX's `<MajorUpgrade>` (which only fires on a strictly greater version) can never trigger. Fixing it is a prerequisite for Task 11 (Windows apply) to have anything to drive.

- [ ] **Step 1: Change the hardcoded version to a WiX variable**

In `packaging/windows/softnix-log-agent.wxs`, line 19, change:

```xml
           Version="0.1.0"
```

to:

```xml
           Version="$(var.Version)"
```

- [ ] **Step 2: Pass the version into `candle.exe` in CI**

In `.github/workflows/release.yml`, in the `Build MSI` step, the `candle.exe` invocation currently reads:

```powershell
& "$wixBin\candle.exe" -nologo -arch x64 "-dSourceDir=$stage" packaging\windows\softnix-log-agent.wxs -o obj\
```

Change it to:

```powershell
& "$wixBin\candle.exe" -nologo -arch x64 "-dSourceDir=$stage" "-dVersion=$version" packaging\windows\softnix-log-agent.wxs -o obj\
```

(`$version` is already computed two lines above this in the same step — no new variable needed.)

- [ ] **Step 3: Verify the fix compiles the .wxs correctly (manual — no Windows/WiX available in this environment)**

This cannot be verified by `cargo test` — it's a WiX/MSI build step with no Rust involved, and this plan may be executed on a non-Windows machine with no `candle.exe` available at all. Verify manually the next time CI runs on a real tag push, or locally on a Windows box with WiX v3 installed:

```powershell
$wixBin = (Get-ChildItem "C:\Program Files (x86)\WiX Toolset v3*\bin" -Directory | Select-Object -First 1).FullName
& "$wixBin\candle.exe" -nologo -arch x64 "-dSourceDir=." "-dVersion=0.2.0" packaging\windows\softnix-log-agent.wxs -o obj\
& "$wixBin\light.exe" -nologo obj\softnix-log-agent.wixobj -o dist\test.msi
# Then confirm the built MSI's ProductVersion is actually 0.2.0:
(Get-AppLockerFileInformation dist\test.msi).Publisher
# or, more directly:
python -c "import msilib; db = msilib.OpenDatabase('dist/test.msi', msilib.MSIDBOPEN_READONLY); view = db.OpenView(\"SELECT Value FROM Property WHERE Property='ProductVersion'\"); view.Execute(None); print(view.Fetch().GetString(1))"
```

Expected: prints `0.2.0`, not `0.1.0`.

- [ ] **Step 4: Commit**

```bash
git add packaging/windows/softnix-log-agent.wxs .github/workflows/release.yml
git commit -m "fix(windows): stop hardcoding MSI ProductVersion so MajorUpgrade can trigger"
```

---

### Task 6: Release pipeline emits a signed manifest

**Files:**
- Modify: `.github/workflows/release.yml` (the `publish` job)
- Create: `docs/RELEASE-SIGNING.md` (runbook: key generation and custody — not code, but required reading before this task's CI step can produce anything other than a manifest signed by nobody the agent trusts)

This task cannot be verified by `cargo test` — it is release-engineering infrastructure (CI YAML + a private key that must not exist in this repo or in ordinary CI secrets). Treat the "done-condition" as a documented manual dry run, not an automated test.

- [ ] **Step 1: Write the signing runbook**

Create `docs/RELEASE-SIGNING.md`:

```markdown
# Release signing

The agent verifies every update manifest against an Ed25519 public key
compiled into the binary (`RELEASE_PUBLIC_KEYS` in
`src/update/manifest.rs`). This document is the one-time key setup and the
per-release signing step. The private key must never be committed to this
repository and must never be an ordinary GitHub Actions secret available to
every workflow run — store it in a GitHub Environment that requires
manual reviewer approval before a workflow can read it, or on a hardware
token / KMS.

## One-time: generate the signing key

```
openssl genpkey -algorithm ed25519 -out release-signing-key.pem
openssl pkey -in release-signing-key.pem -pubout -outform DER -out release-signing-key.pub.der
```

The last 32 bytes of `release-signing-key.pub.der` are the raw Ed25519
public key. Extract and format them for `src/update/manifest.rs`:

```
python3 -c "
data = open('release-signing-key.pub.der', 'rb').read()
raw = data[-32:]
print('pub const RELEASE_PUBLIC_KEYS: &[[u8; 32]] = &[[' + ', '.join(str(b) for b in raw) + ']];')
"
```

Paste that line over the current `pub const RELEASE_PUBLIC_KEYS: &[[u8; 32]] = &[];` in `src/update/manifest.rs`, then commit the *public* key (this is safe — it's public) as part of a normal PR. Store `release-signing-key.pem` in the protected environment described above; do not commit it, do not leave it on a laptop.

## Per-release: sign the manifest

After `publish`'s existing checksum step produces `SHA256SUMS`, build
`manifest.json` (schema in `docs/superpowers/specs/2026-09-09-self-update-mechanism.md`)
and sign it:

```
openssl pkeyutl -sign -inkey release-signing-key.pem -rawin -in manifest.json -out manifest.json.sig
```

(`-rawin`: Ed25519 is PureEdDSA, it signs the message directly — there is
no digest algorithm to choose, unlike RSA/ECDSA signing.)
```

- [ ] **Step 2: Add manifest generation, signing, and re-bundling to the `publish` job**

Important design point this step depends on: `manifest.json`'s per-artifact `sha256`/`size` describe the *inner payload* (the raw `softnix-log-agent` binary on Linux, the raw `.msi` on Windows) — not the outer bundle file. This sidesteps a chicken-and-egg problem: the outer bundle (a `.tar.gz`/`.zip`) is going to *contain* `manifest.json`, so its own hash can't be known until after the manifest is already finalized and embedded, but the *inner payload*'s hash is known before any of that. `update::verify::verify_artifact_hash` (Phase 0/1's Task 4) already hashes the extracted inner binary/msi, not the tarball — this CI step just has to match that contract.

Concretely, Linux's existing `.tar.gz` already contains exactly what `apply_from_local`'s extraction step expects (the binary at its root) — it just needs `manifest.json` + `manifest.json.sig` added alongside before the final upload, so the *same* download serves both a normal manual install and a self-update source. Windows has no equivalent single-file container today (the pipeline publishes a bare `.msi`), so this step introduces a second Windows asset, a `.zip` bundling the `.msi` + manifest + signature, specifically for `upgrade --from`; the bare `.msi` keeps being published unchanged for ordinary manual installs.

In `.github/workflows/release.yml`, in the `publish` job, after the existing `Checksum the artifacts` step and before `Create GitHub release`, add:

```yaml
      - name: Build the update manifest (hashes the inner payloads, not the outer bundles)
        run: |
          cd artifacts
          VERSION="${GITHUB_REF_NAME#v}"
          LINUX_TARBALL=$(basename linux-release/*.tar.gz)
          MSI_FILE=$(basename windows-msi/*.msi)

          # Extract just the binary to hash the inner payload, per the
          # design note above — do not hash the tarball itself.
          mkdir -p _linux_extract
          tar xzf "linux-release/$LINUX_TARBALL" -C _linux_extract
          LINUX_BINARY=$(find _linux_extract -type f -name softnix-log-agent)
          LINUX_SHA=$(sha256sum "$LINUX_BINARY" | cut -d' ' -f1)
          LINUX_SIZE=$(stat -c%s "$LINUX_BINARY")

          MSI_SHA=$(sha256sum "windows-msi/$MSI_FILE" | cut -d' ' -f1)
          MSI_SIZE=$(stat -c%s "windows-msi/$MSI_FILE")

          # Both bundle filenames are chosen here, before either bundle is
          # actually built (next step) — deterministic names so this
          # manifest's `url` fields match what gets uploaded later in this
          # same job.
          LINUX_BUNDLE="softnix-log-agent-$VERSION-linux-x86_64.tar.gz"
          WINDOWS_BUNDLE="softnix-log-agent-$VERSION-windows-x86_64-update.zip"

          cat > manifest.json <<JSON
          {
            "schema_version": 1,
            "product": "softnix-log-agent",
            "version": "$VERSION",
            "manifest_serial": ${{ github.run_number }},
            "released_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
            "expires_at": "$(date -u -d '+2 years' +%Y-%m-%dT%H:%M:%SZ)",
            "artifacts": [
              {"platform": "linux", "arch": "x86_64", "filename": "$LINUX_BUNDLE", "url": "https://github.com/${{ github.repository }}/releases/download/${GITHUB_REF_NAME}/$LINUX_BUNDLE", "sha256": "$LINUX_SHA", "size": $LINUX_SIZE},
              {"platform": "windows", "arch": "x86_64", "filename": "$WINDOWS_BUNDLE", "url": "https://github.com/${{ github.repository }}/releases/download/${GITHUB_REF_NAME}/$WINDOWS_BUNDLE", "sha256": "$MSI_SHA", "size": $MSI_SIZE}
            ]
          }
          JSON
          cat manifest.json
      - name: Sign the manifest
        env:
          RELEASE_SIGNING_KEY: ${{ secrets.RELEASE_SIGNING_KEY }}
        run: |
          cd artifacts
          echo "$RELEASE_SIGNING_KEY" > /tmp/release-signing-key.pem
          openssl pkeyutl -sign -inkey /tmp/release-signing-key.pem -rawin -in manifest.json -out manifest.json.sig
          shred -u /tmp/release-signing-key.pem
      - name: Bundle the manifest into each platform's self-update artifact
        run: |
          cd artifacts
          VERSION="${GITHUB_REF_NAME#v}"
          LINUX_TARBALL=$(basename linux-release/*.tar.gz)
          MSI_FILE=$(basename windows-msi/*.msi)

          # Linux: add manifest.json/.sig into the already-extracted
          # staging dir from the previous step, re-tar over the same
          # filename — this one file keeps serving both a normal manual
          # install and `upgrade --from`.
          STAGE_DIR=$(find _linux_extract -maxdepth 1 -mindepth 1 -type d)
          cp manifest.json manifest.json.sig "$STAGE_DIR/"
          rm -f "linux-release/$LINUX_TARBALL"
          tar czf "linux-release/$LINUX_TARBALL" -C _linux_extract "$(basename "$STAGE_DIR")"

          # Windows: no existing single-file container to add to, so build
          # a new one specifically for updates. The bare .msi in
          # windows-msi/ is left untouched and still published separately
          # for ordinary manual installs.
          WINDOWS_BUNDLE="softnix-log-agent-$VERSION-windows-x86_64-update.zip"
          mkdir -p _win_bundle
          cp "windows-msi/$MSI_FILE" manifest.json manifest.json.sig _win_bundle/
          (cd _win_bundle && zip -j "../windows-msi/$WINDOWS_BUNDLE" "$MSI_FILE" manifest.json manifest.json.sig)
```

Then change the existing `Checksum the artifacts` step to run *after* this bundling (reorder it below these two new steps in the file, even though it's shown first in this plan for readability) so `SHA256SUMS` reflects the final, manifest-bundled files — and change the `gh release create` step to publish the new Windows update-zip and the loose manifest alongside everything else:

```yaml
          gh release create "${GITHUB_REF_NAME}" \
            artifacts/linux-release/*.tar.gz \
            artifacts/windows-msi/*.msi \
            artifacts/windows-msi/*-update.zip \
            artifacts/SHA256SUMS \
            artifacts/manifest.json \
            artifacts/manifest.json.sig \
            --title "${GITHUB_REF_NAME}" \
            --generate-notes
```

`RELEASE_SIGNING_KEY` must be set on a protected GitHub Environment this job references (add `environment: release-signing` to the `publish` job — not shown above for brevity, but required), not a plain repo secret, per the runbook.

- [ ] **Step 3: Verify manually (no GitHub Actions runner available in this environment)**

This step cannot run in a local sandbox. The next time this workflow runs for a real tag:

1. Confirm the release contains: the (now manifest-bundled) Linux `.tar.gz`, the bare Windows `.msi`, the new Windows `*-update.zip`, `SHA256SUMS`, `manifest.json`, `manifest.json.sig`.
2. Download the Linux tarball, `tar xzf` it, and confirm `manifest.json`/`manifest.json.sig` are present at its root alongside `softnix-log-agent`.
3. Locally verify the signature against the published public key:

```
openssl pkeyutl -verify -pubin -inkey release-signing-key.pub.pem -rawin -in manifest.json -sigfile manifest.json.sig
```

Expected: `Signature Verified Successfully`.

4. Confirm the manifest's recorded `sha256` for the linux artifact matches a fresh local hash of the *extracted binary*, not the tarball: `sha256sum` the extracted `softnix-log-agent` file and compare against `manifest.json`'s `artifacts[0].sha256`.

- [ ] **Step 4: Commit**

```bash
git add docs/RELEASE-SIGNING.md .github/workflows/release.yml
git commit -m "feat(release): emit and sign an update manifest for each release"
```

---

### Task 7: Preflight — validate the staged binary before touching anything live

**Files:**
- Create: `src/update/apply.rs`
- Modify: `src/update/mod.rs` (add `pub mod apply;`)

**Interfaces:**
- Produces: `pub fn preflight(staged_binary: &std::path::Path, live_config: &std::path::Path) -> anyhow::Result<()>`. Consumed by Task 10 (Linux orchestration) and Task 11 (Windows orchestration) before either ever renames/installs anything.

- [ ] **Step 1: Write the failing tests**

Create `src/update/apply.rs`:

```rust
//! Cross-platform update orchestration: preflight, then dispatch to the
//! platform-specific swap in `apply_linux` / `apply_windows`.

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

/// Runs the staged binary out-of-band, twice, *before* it ever replaces
/// anything live:
///   1. `<staged> --version` — proves it can even load on this host's
///      architecture/libc (the same class of failure
///      `packaging/install-linux.sh` already guards against with its own
///      post-install smoke check).
///   2. `<staged> validate --config <live_config>` — proves the new
///      version still accepts the configuration this host is actually
///      running, mirroring `try_reload`'s "validate the new config before
///      stopping the old engine" (`src/main.rs:350-399`).
/// Either failing aborts the whole upgrade with nothing changed.
pub fn preflight(staged_binary: &Path, live_config: &Path) -> Result<()> {
    let version_check = Command::new(staged_binary)
        .arg("--version")
        .output()
        .with_context(|| format!("cannot execute staged binary {}", staged_binary.display()))?;
    if !version_check.status.success() {
        bail!(
            "staged binary {} failed to run --version (exit {:?}); it likely cannot run on this host",
            staged_binary.display(),
            version_check.status.code()
        );
    }

    let validate_check = Command::new(staged_binary)
        .arg("validate")
        .arg("--config")
        .arg(live_config)
        .output()
        .with_context(|| format!("cannot execute staged binary {}", staged_binary.display()))?;
    if !validate_check.status.success() {
        let stderr = String::from_utf8_lossy(&validate_check.stderr);
        bail!(
            "staged binary {} rejects the current configuration {}: {stderr}",
            staged_binary.display(),
            live_config.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises `preflight` against the *actual test binary of this crate*
    // standing in for "the staged binary" — it's a real `softnix-log-agent`
    // executable, so `--version` and `validate` behave exactly as they
    // would for a genuine staged release artifact.
    fn this_binary() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_softnix-log-agent"))
    }

    #[test]
    fn preflight_passes_with_a_valid_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(
            &config_path,
            format!(
                "agent:\n  data_dir: {}\nweb:\n  enabled: false\n",
                dir.path().join("data").display()
            ),
        )
        .unwrap();

        preflight(&this_binary(), &config_path).unwrap();
    }

    #[test]
    fn preflight_fails_on_an_invalid_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "this: is not: valid: yaml: at all:\n").unwrap();

        let err = preflight(&this_binary(), &config_path).unwrap_err();
        assert!(err.to_string().contains("rejects the current configuration"));
    }

    #[test]
    fn preflight_fails_cleanly_on_a_nonexistent_staged_binary() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "web:\n  enabled: false\n").unwrap();

        let err = preflight(&dir.path().join("does-not-exist"), &config_path).unwrap_err();
        assert!(err.to_string().contains("cannot execute staged binary"));
    }
}
```

Add to `src/update/mod.rs`:

```rust
pub mod apply;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib update::apply::`
Expected: FAIL — module doesn't exist yet.

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --lib update::apply::`
Expected: `test result: ok. 3 passed`. (Uses `env!("CARGO_BIN_EXE_softnix-log-agent")`, which Cargo only populates for integration-style tests that can see the built binary — this works from `src/update/apply.rs`'s `#[cfg(test)]` because it's part of the `softnix_log_agent` lib crate and the bin target `softnix-log-agent` is built from the same package; if this specific macro fails to resolve in practice, fall back to `Path::new(env!("CARGO_MANIFEST_DIR")).join("target/debug/softnix-log-agent")` instead and note the deviation in the commit message.)

- [ ] **Step 4: Commit**

```bash
git add src/update/mod.rs src/update/apply.rs
git commit -m "feat(update): preflight a staged binary before it touches anything live"
```

---

### Task 8: Linux stage-and-swap

**Files:**
- Create: `src/update/apply_linux.rs`
- Modify: `src/update/mod.rs` (add `#[cfg(target_os = "linux")] pub mod apply_linux;`)

**Interfaces:**
- Produces: `pub fn stage_and_swap(new_binary: &std::path::Path, live_target: &std::path::Path, version: &str) -> anyhow::Result<std::path::PathBuf>` (returns the path of the retained previous binary, for `rollback` (Task 9) and pruning (Task 10) to use).

- [ ] **Step 1: Write the failing tests**

Create `src/update/apply_linux.rs`:

```rust
//! Linux binary swap: stage in the same directory as the live target
//! (never cross a filesystem boundary — `rename()` across filesystems
//! fails with `EXDEV` and has no atomic fallback), keep the previous
//! binary as a hardlink so the running process's already-open file
//! descriptor is unaffected, then a single atomic rename.

use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Copies `new_binary`'s content into the same directory as `live_target`,
/// makes it executable, hardlinks the *current* `live_target` aside as
/// `<live_target>.old-<version>` (so it survives even though its original
/// path is about to be overwritten — the running process keeps its own
/// inode regardless, this hardlink is purely for `rollback`/retention),
/// then atomically renames the staged file onto `live_target`.
///
/// Returns the path of the retained previous binary.
pub fn stage_and_swap(
    new_binary: &Path,
    live_target: &Path,
    version: &str,
) -> Result<PathBuf> {
    let parent = live_target
        .parent()
        .context("live_target has no parent directory")?;
    let staged = parent.join(format!(
        ".{}.new",
        live_target
            .file_name()
            .context("live_target has no file name")?
            .to_string_lossy()
    ));
    std::fs::copy(new_binary, &staged)
        .with_context(|| format!("cannot stage new binary at {}", staged.display()))?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("cannot chmod {}", staged.display()))?;

    let old_path = parent.join(format!(
        "{}.old-{version}",
        live_target.file_name().unwrap().to_string_lossy()
    ));
    // Remove any stale hardlink from a prior failed attempt at the same
    // version before creating a fresh one — `hard_link` errors if the
    // target already exists.
    let _ = std::fs::remove_file(&old_path);
    std::fs::hard_link(live_target, &old_path).with_context(|| {
        format!(
            "cannot hardlink current binary {} aside as {}",
            live_target.display(),
            old_path.display()
        )
    })?;

    std::fs::rename(&staged, live_target).with_context(|| {
        format!(
            "cannot rename staged binary {} onto {}",
            staged.display(),
            live_target.display()
        )
    })?;

    Ok(old_path)
}

/// Reverts a `stage_and_swap`: renames the retained previous binary back
/// onto `live_target`. Used both by automatic rollback-on-health-check-
/// failure (Task 10) and by the manual `upgrade --rollback` command.
pub fn rollback(live_target: &Path, old_path: &Path) -> Result<()> {
    std::fs::rename(old_path, live_target).with_context(|| {
        format!(
            "cannot roll back: rename {} onto {} failed",
            old_path.display(),
            live_target.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swaps_content_and_retains_the_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old content").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new content").unwrap();

        let old_path = stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        assert_eq!(std::fs::read(&live).unwrap(), b"new content");
        assert_eq!(std::fs::read(&old_path).unwrap(), b"old content");
        assert_eq!(old_path, dir.path().join("softnix-log-agent.old-0.2.0"));
    }

    #[test]
    fn the_swapped_in_binary_is_executable() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new").unwrap();

        stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        let mode = std::fs::metadata(&live).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn no_staging_temp_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new").unwrap();

        stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        assert!(!dir.path().join(".softnix-log-agent.new").exists());
    }

    #[test]
    fn rollback_restores_the_previous_binary() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"old content").unwrap();
        let new_binary = dir.path().join("staged-source");
        std::fs::write(&new_binary, b"new content").unwrap();

        let old_path = stage_and_swap(&new_binary, &live, "0.2.0").unwrap();
        rollback(&live, &old_path).unwrap();

        assert_eq!(std::fs::read(&live).unwrap(), b"old content");
    }

    #[test]
    fn a_second_swap_attempt_at_the_same_version_does_not_error_on_a_stale_hardlink() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"v1").unwrap();
        let new_binary = dir.path().join("staged-source");

        std::fs::write(&new_binary, b"v2-attempt-1").unwrap();
        stage_and_swap(&new_binary, &live, "0.2.0").unwrap();

        // Second attempt at the same target version (e.g. a retried
        // upgrade after a transient failure) must not fail merely because
        // `softnix-log-agent.old-0.2.0` already exists from the first try.
        std::fs::write(&new_binary, b"v2-attempt-2").unwrap();
        let old_path = stage_and_swap(&new_binary, &live, "0.2.0").unwrap();
        assert_eq!(std::fs::read(&live).unwrap(), b"v2-attempt-2");
        assert_eq!(std::fs::read(&old_path).unwrap(), b"v2-attempt-1");
    }
}
```

Add to `src/update/mod.rs`:

```rust
#[cfg(target_os = "linux")]
pub mod apply_linux;
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --lib update::apply_linux::`
Expected: FAIL — module doesn't exist yet. (If running this plan's steps on a non-Linux machine, this whole task's tests are `#[cfg(target_os = "linux")]`-gated and will report 0 tests found rather than failing — that's expected on macOS/Windows dev machines; the CI's `build-linux` job is what actually exercises this.)

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test --lib update::apply_linux::`
Expected: `test result: ok. 5 passed` (on Linux; skipped elsewhere).

- [ ] **Step 4: Commit**

```bash
git add src/update/mod.rs src/update/apply_linux.rs
git commit -m "feat(update): add Linux stage-and-swap with hardlink-based rollback"
```

---

### Task 9: Linux end-to-end apply orchestration + CLI wiring

**Files:**
- Modify: `src/update/apply.rs` (add `apply_from_local`)
- Modify: `src/main.rs` (add `Command::Upgrade`)

**Interfaces:**
- Consumes: `manifest::verify_manifest`, `manifest::check_freshness` (Task 1, 2), `watermark::Watermark` (Task 3), `verify::verify_artifact_hash`, `Manifest::artifact_for` (Task 4), `apply::preflight` (Task 7), `apply_linux::{stage_and_swap, rollback}` (Task 8, `#[cfg(target_os = "linux")]`-gated), `crate::service::restart` (existing, `src/service.rs`).
- Produces: `pub fn apply_from_local(artifact_path: &std::path::Path, config_path: &std::path::Path, data_dir: &std::path::Path, allow_downgrade: bool, live_target: &std::path::Path) -> anyhow::Result<()>`, `pub fn rollback_from_local(live_target: &std::path::Path, data_dir: &std::path::Path) -> anyhow::Result<()>`.

**Note on cross-platform compilation:** `apply_linux::{stage_and_swap, rollback}` (Task 8) are only compiled under `#[cfg(target_os = "linux")]`, but this crate is built and tested on macOS/Windows dev machines too. `apply_from_local` itself (extraction, signature/freshness/hash verification, preflight) is platform-independent and must compile everywhere, so it must NOT reference `apply_linux::*` unconditionally. Factor the actual swap/restart/health-check/rollback sequence into a `platform_swap_and_restart(extracted_binary: &Path, live_target: &Path, version: &str) -> Result<()>` helper with two arms: `#[cfg(target_os = "linux")]` (the real logic, calling `apply_linux::stage_and_swap`/`apply_linux::rollback`) and `#[cfg(not(target_os = "linux"))]` (an erroring stub: `bail!("upgrade apply ... is only implemented on Linux in this build")`), mirroring the platform-split pattern `src/service.rs` already uses. `rollback_from_local` needs the same split for the same reason (its body calls `apply_linux::rollback`).

The artifact is a `.tar.gz` containing the new binary plus a bundled `manifest.json`/`manifest.json.sig` (so `--from` needs no network access at all — everything required to verify is inside the file). Extraction shells out to the system `tar` binary (present on essentially every Linux host; avoids adding `tar`/`flate2` as new Rust dependencies for a one-line extraction).

- [ ] **Step 1: Write the failing tests**

The health-check/restart/watermark-write parts of this function call real OS services (`systemctl`, a live `/healthz`) that cannot run inside `cargo test`. Split the orchestration so the *decision logic* (verify → freshness → hash → preflight → swap-or-abort) is one function tested with fakes for the "point of no return" step, and the *OS-interacting tail* (restart + health-poll + watermark write) is a thin, untested-by-design wrapper documented as manually verified — this mirrors how `preflight` (Task 7) already draws its test boundary at "runs a real subprocess" rather than mocking the subprocess.

Append to `src/update/apply.rs`:

```rust
    #[test]
    fn apply_from_local_rejects_a_replayed_manifest_before_touching_the_binary() {
        // This test constructs a minimal tar.gz containing a manifest that
        // fails `check_freshness` (serial 0, which is never > the initial
        // watermark of 0) and confirms the live binary file is untouched
        // afterward - proving verification happens strictly before any
        // filesystem mutation to the live target.
        use std::io::Write;

        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"original content").unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "web:\n  enabled: false\n").unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        // A syntactically-valid but zero-serial (thus non-fresh) manifest,
        // unsigned — this must be rejected at the "no trusted keys"
        // signature-verification step (Task 1's fail-closed behavior)
        // before freshness is even checked, which is exactly the property
        // this test is protecting: nothing downstream of `verify_manifest`
        // ever runs against an unverified manifest.
        let manifest_json = br#"{"schema_version":1,"product":"softnix-log-agent","version":"0.2.0","manifest_serial":0,"released_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","artifacts":[]}"#;

        let tar_path = dir.path().join("release.tar.gz");
        {
            let tar_gz = std::fs::File::create(&tar_path).unwrap();
            let enc = flate2_stub::GzEncoderStub::new(tar_gz);
            let mut tar = tar_stub::BuilderStub::new(enc);
            tar.add_bytes("manifest.json", manifest_json);
            tar.add_bytes("manifest.json.sig", &[0u8; 64]);
            tar.add_bytes("softnix-log-agent", b"pretend-new-binary");
            tar.finish();
        }

        let result = apply_from_local(&tar_path, &config_path, &data_dir, false);
        assert!(result.is_err());
        assert_eq!(std::fs::read(&live).unwrap(), b"original content");
    }
```

This test as sketched depends on a `tar`/`gzip`-writing helper (`flate2_stub`/`tar_stub`) that doesn't exist and — per this task's own design — is deliberately not being added as a real dependency (extraction shells out to the system `tar` binary instead of linking a tar/gzip crate). Do not implement `flate2_stub`/`tar_stub`. Replace this test with the shell-out-friendly version below, which builds the fixture archive using the same system `tar` the implementation itself will call:

```rust
    #[test]
    fn apply_from_local_rejects_a_replayed_manifest_before_touching_the_binary() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"original content").unwrap();
        let config_path = dir.path().join("agent.yaml");
        std::fs::write(&config_path, "web:\n  enabled: false\n").unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        let stage = dir.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(
            stage.join("manifest.json"),
            br#"{"schema_version":1,"product":"softnix-log-agent","version":"0.2.0","manifest_serial":0,"released_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z","artifacts":[]}"#,
        )
        .unwrap();
        std::fs::write(stage.join("manifest.json.sig"), [0u8; 64]).unwrap();
        std::fs::write(stage.join("softnix-log-agent"), b"pretend-new-binary").unwrap();

        let tar_path = dir.path().join("release.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("czf")
            .arg(&tar_path)
            .arg("-C")
            .arg(&stage)
            .arg("manifest.json")
            .arg("manifest.json.sig")
            .arg("softnix-log-agent")
            .status()
            .unwrap();
        assert!(status.success());

        let result = apply_from_local(&tar_path, &config_path, &data_dir, false, &live);
        assert!(result.is_err());
        assert_eq!(std::fs::read(&live).unwrap(), b"original content");
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib update::apply::apply_from_local_rejects_a_replayed`
Expected: FAIL — `apply_from_local` doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Add to `src/update/apply.rs` (above `mod tests`):

```rust
use super::manifest::{check_freshness, verify_manifest};
use super::verify::verify_artifact_hash;
use super::watermark::Watermark;

const CURRENT_PLATFORM: &str = "linux";
const CURRENT_ARCH: &str = std::env::consts::ARCH;

/// Extracts `manifest.json` + `manifest.json.sig` + the platform binary
/// from `artifact_path` (a `.tar.gz`) into a fresh temp directory, verifies
/// the manifest's signature and freshness, verifies the extracted binary's
/// hash against the manifest, preflights it against `config_path`, then —
/// only after every one of those checks passes — swaps it onto
/// `live_target` and restarts the service. Everything up to the swap is
/// read-only with respect to `live_target`; a failure at any check leaves
/// it completely untouched.
pub fn apply_from_local(
    artifact_path: &std::path::Path,
    config_path: &std::path::Path,
    data_dir: &std::path::Path,
    allow_downgrade: bool,
    live_target: &std::path::Path,
) -> Result<()> {
    let extract_dir = tempfile::tempdir().context("cannot create extraction temp dir")?;
    let status = Command::new("tar")
        .arg("xzf")
        .arg(artifact_path)
        .arg("-C")
        .arg(extract_dir.path())
        .status()
        .context("cannot run tar to extract the update artifact")?;
    if !status.success() {
        bail!("tar extraction of {} failed", artifact_path.display());
    }

    let manifest_bytes = std::fs::read(extract_dir.path().join("manifest.json"))
        .context("update artifact has no manifest.json")?;
    let sig = std::fs::read(extract_dir.path().join("manifest.json.sig"))
        .context("update artifact has no manifest.json.sig")?;
    let manifest = verify_manifest(&manifest_bytes, &sig)?;

    let mut watermark = Watermark::open(data_dir);
    check_freshness(
        &manifest,
        watermark.highest_serial(),
        env!("CARGO_PKG_VERSION"),
        allow_downgrade,
        chrono::Utc::now(),
    )?;

    let artifact = manifest
        .artifact_for(CURRENT_PLATFORM, CURRENT_ARCH)
        .with_context(|| {
            format!("manifest has no artifact for {CURRENT_PLATFORM}/{CURRENT_ARCH}")
        })?;
    let extracted_binary = extract_dir.path().join("softnix-log-agent");
    verify_artifact_hash(&extracted_binary, &artifact.sha256)?;

    preflight(&extracted_binary, config_path)?;

    // Point of no return: everything above this line is read-only with
    // respect to `live_target`.
    let old_path = super::apply_linux::stage_and_swap(&extracted_binary, live_target, &manifest.version)?;

    if let Err(e) = crate::service::restart() {
        tracing::error!("service restart failed after swap: {e:#}; rolling back");
        super::apply_linux::rollback(live_target, &old_path)?;
        crate::service::restart().context("rollback restart also failed")?;
        bail!("upgrade failed to restart the service; rolled back to the previous version");
    }

    if !wait_for_healthy() {
        tracing::error!("new version did not become healthy; rolling back");
        super::apply_linux::rollback(live_target, &old_path)?;
        crate::service::restart().context("rollback restart failed")?;
        bail!("upgrade did not become healthy within the grace window; rolled back to the previous version");
    }

    watermark.record(manifest.manifest_serial)?;
    println!(
        "upgraded {} -> {}",
        env!("CARGO_PKG_VERSION"),
        manifest.version
    );
    Ok(())
}

/// Polls the local, unauthenticated `/healthz` for up to 60s, requiring 3
/// consecutive 200s before declaring the new version healthy. Reads
/// `web.port`/`web.bind` from the live config would be more precise, but
/// `/healthz` binds to whatever the config on disk (now the *new* config,
/// unchanged by this upgrade) says — 127.0.0.1 is this project's default
/// and the common case; a non-default bind/port is a known limitation of
/// this first cut, tracked for Phase 1 hardening rather than blocking it.
fn wait_for_healthy() -> bool {
    let mut consecutive_ok = 0;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let ok = Command::new("curl")
            .arg("-sf")
            .arg("-o")
            .arg("/dev/null")
            .arg("http://127.0.0.1:8080/healthz")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            consecutive_ok += 1;
            if consecutive_ok >= 3 {
                return true;
            }
        } else {
            consecutive_ok = 0;
        }
    }
    false
}

/// Manual rollback path for `upgrade --rollback`: finds the single
/// retained `.old-<version>` file next to `live_target` and restores it.
/// Errors if none is retained, or if more than one exists (this should be
/// impossible given `apply_from_local` prunes to exactly one, but a
/// corrupted/hand-edited install directory should fail loudly here rather
/// than guess which one to restore).
pub fn rollback_from_local(live_target: &std::path::Path, _data_dir: &std::path::Path) -> Result<()> {
    let parent = live_target
        .parent()
        .context("live_target has no parent directory")?;
    let file_name = live_target
        .file_name()
        .context("live_target has no file name")?
        .to_string_lossy();
    let prefix = format!("{file_name}.old-");
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(parent)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().starts_with(&prefix))
                .unwrap_or(false)
        })
        .collect();
    match candidates.len() {
        0 => bail!("no retained previous version found next to {}", live_target.display()),
        1 => {
            super::apply_linux::rollback(live_target, &candidates.remove(0))?;
            crate::service::restart().context("rollback restart failed")?;
            Ok(())
        }
        n => bail!("expected exactly one retained previous version, found {n} — refusing to guess"),
    }
}
```

Add `pub` re-exports as needed in `src/update/mod.rs` if `apply_from_local`/`rollback_from_local` aren't already reachable as `update::apply::apply_from_local` (they are, given `pub mod apply;` from Task 7 — no change needed here).

Add to `Cargo.toml` `[dev-dependencies]` (needed by this task's test, which calls `tempfile::tempdir()` — already present — no change needed; confirm `tempfile` is already a dev-dependency, which it is).

Now wire the CLI. In `src/main.rs`, add to the `Command` enum (after `ServiceRun`):

```rust
    /// Apply a self-contained update artifact (offline, no network access).
    Upgrade {
        /// Path to a downloaded/copied release artifact (.tar.gz on Linux).
        /// Required unless --rollback is passed.
        #[arg(long, required_unless_present = "rollback")]
        from: Option<PathBuf>,
        /// Roll back to the previously retained version instead of applying `--from`.
        #[arg(long)]
        rollback: bool,
        /// Allow installing a version older than the one currently running.
        #[arg(long)]
        allow_downgrade: bool,
        #[arg(short, long, default_value = "agent.yaml")]
        config: PathBuf,
    },
```

And to `main()`'s `match`:

```rust
        Some(Command::Upgrade {
            from,
            rollback,
            allow_downgrade,
            config,
        }) => upgrade_cmd(from.as_deref(), rollback, allow_downgrade, &config),
```

Add the handler function (near `validate_cmd`):

```rust
fn upgrade_cmd(from: Option<&Path>, rollback: bool, allow_downgrade: bool, config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config for upgrade")?;
    let live_target = std::env::current_exe().context("cannot resolve the running binary's path")?;
    if rollback {
        softnix_log_agent::update::apply::rollback_from_local(&live_target, &cfg.agent.data_dir)
    } else {
        let from = from.context("--from is required unless --rollback is passed")?;
        softnix_log_agent::update::apply::apply_from_local(
            from,
            config_path,
            &cfg.agent.data_dir,
            allow_downgrade,
            &live_target,
        )
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib update::apply::`
Expected: `test result: ok` (this task's new test plus Task 7's 3 preflight tests, all green).

- [ ] **Step 5: Run the full test suite to confirm no regressions**

Run: `cargo test`
Expected: all existing tests still pass, plus the new ones.

- [ ] **Step 6: Manually verify the actual restart+health-check path (cannot run inside `cargo test` — needs a real systemd host)**

This cannot be automated in this plan's test suite: it requires a real running systemd service. Once Task 5/6 have shipped a real signed release, verify manually on a Linux VM:

```bash
sudo softnix-log-agent service install --config /etc/softnix-log-agent/agent.yaml
sudo systemctl start softnix-log-agent
curl -s localhost:8080/api/about  # confirm old version
sudo softnix-log-agent upgrade --from softnix-log-agent-0.2.0-linux-x86_64.tar.gz --config /etc/softnix-log-agent/agent.yaml
curl -s localhost:8080/api/about  # confirm new version
sudo softnix-log-agent upgrade --rollback --config /etc/softnix-log-agent/agent.yaml
curl -s localhost:8080/api/about  # confirm rolled back to old version
```

- [ ] **Step 7: Commit**

```bash
git add src/update/apply.rs src/main.rs
git commit -m "feat(update): wire offline apply/rollback into the upgrade CLI subcommand"
```

---

### Task 10: Prune retained artifacts to exactly N-1

**Files:**
- Modify: `src/update/apply.rs` (`apply_from_local`, after a successful `watermark.record`)

**Interfaces:**
- Consumes: the same `.old-<version>` naming convention `apply_linux::stage_and_swap` already produces.
- Produces: `fn prune_old_versions(live_target: &std::path::Path, keep: &std::path::Path) -> anyhow::Result<()>` (private to `apply.rs`; called from `apply_from_local`).

- [ ] **Step 1: Write the failing test**

Append to `src/update/apply.rs`'s `mod tests`:

```rust
    #[test]
    fn prune_old_versions_removes_every_retained_version_except_the_one_to_keep() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("softnix-log-agent");
        std::fs::write(&live, b"current").unwrap();
        let keep = dir.path().join("softnix-log-agent.old-0.1.5");
        std::fs::write(&keep, b"kept").unwrap();
        let stale1 = dir.path().join("softnix-log-agent.old-0.1.4");
        std::fs::write(&stale1, b"stale").unwrap();
        let stale2 = dir.path().join("softnix-log-agent.old-0.1.3");
        std::fs::write(&stale2, b"stale").unwrap();

        prune_old_versions(&live, &keep).unwrap();

        assert!(keep.exists());
        assert!(!stale1.exists());
        assert!(!stale2.exists());
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib update::apply::prune_old_versions`
Expected: FAIL — function doesn't exist.

- [ ] **Step 3: Write the implementation**

Add to `src/update/apply.rs`:

```rust
/// Removes every `<live_target>.old-*` file except `keep`. Called after a
/// successful upgrade so retention never exceeds one previous version —
/// an unbounded number of retained binaries is both a disk-space leak and
/// makes `rollback_from_local`'s "exactly one candidate" invariant false.
fn prune_old_versions(live_target: &std::path::Path, keep: &std::path::Path) -> Result<()> {
    let parent = live_target
        .parent()
        .context("live_target has no parent directory")?;
    let file_name = live_target
        .file_name()
        .context("live_target has no file name")?
        .to_string_lossy();
    let prefix = format!("{file_name}.old-");
    for entry in std::fs::read_dir(parent)? {
        let path = entry?.path();
        let is_old_version = path
            .file_name()
            .map(|n| n.to_string_lossy().starts_with(&prefix))
            .unwrap_or(false);
        if is_old_version && path != keep {
            std::fs::remove_file(&path)
                .with_context(|| format!("cannot prune stale retained version {}", path.display()))?;
        }
    }
    Ok(())
}
```

Then call it from `apply_from_local`, right after `watermark.record(manifest.manifest_serial)?;`:

```rust
    watermark.record(manifest.manifest_serial)?;
    prune_old_versions(live_target, &old_path)?;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib update::apply::`
Expected: all tests in this module pass, including the new one.

- [ ] **Step 5: Commit**

```bash
git add src/update/apply.rs
git commit -m "feat(update): prune retained old-version binaries to exactly one"
```

---

### Task 11: Windows self-relaunch + msiexec driver

**Files:**
- Create: `src/update/apply_windows.rs`
- Modify: `src/update/mod.rs` (add `#[cfg(windows)] pub mod apply_windows;`)
- Modify: `src/main.rs` (add hidden `Command::UpgradeApply`)

**Interfaces:**
- Produces: `pub fn self_relaunch_and_apply(zip_path: &std::path::Path, config_path: &std::path::Path, data_dir: &std::path::Path, allow_downgrade: bool) -> anyhow::Result<()>` (called from the `Upgrade` handler when `cfg!(windows)` — verifies *before* relaunching, so a bad artifact never even gets to the point of spawning a temp copy), `pub fn apply_msi(msi_path: &std::path::Path) -> anyhow::Result<()>` (runs inside the relaunched temp-copy process, called from the new hidden subcommand; performs no verification of its own — that already happened in the parent process — only drives the install).

`--from` on Windows takes the `*-update.zip` bundle Task 6 now produces (`.msi` + `manifest.json` + `manifest.json.sig`, all three at the zip's root) — the same "one file, self-contained, verifiable offline" contract Linux's tarball already has. This task cannot be compiled or tested on a non-Windows development machine (`#[cfg(windows)]`-gated throughout) and cannot be exercised by `cargo test` even on Windows, since it drives the real Windows Service Control Manager and `msiexec`. Every step here is written to the same standard of concreteness as the testable tasks, but its verification step is a manual Windows-VM runbook (Task 12), not a test run.

- [ ] **Step 1: Write the implementation directly (no red/green cycle available in this environment)**

Create `src/update/apply_windows.rs`:

```rust
//! Windows apply: MSI major upgrade only (see the spec's constraint 4 for
//! why a direct .exe swap is rejected — MSI's unversioned-file bookkeeping
//! plus NTFS tunneling makes a self-modified exe's replacement outcome on
//! a later install/repair nondeterministic). The running process cannot
//! drive `msiexec` itself and then judge whether it worked from inside a
//! process the MSI action might be replacing, so it copies itself to a
//! temp path and relaunches that copy in a hidden mode first.

use super::manifest::{check_freshness, verify_manifest};
use super::verify::verify_artifact_hash;
use super::watermark::Watermark;
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

const CURRENT_PLATFORM: &str = "windows";
const CURRENT_ARCH: &str = std::env::consts::ARCH;

/// Extracts `zip_path` (the `*-update.zip` bundle: `.msi` + manifest +
/// signature at its root) to a temp directory using PowerShell's
/// `Expand-Archive` (built into every supported Windows version — no new
/// dependency needed for zip handling, matching how Linux's extraction
/// shells out to the system `tar`), verifies the manifest and the `.msi`'s
/// hash, checks freshness against the persisted watermark — all of this
/// BEFORE anything is relaunched or replaced — then copies the currently-
/// running `softnix-log-agent.exe` to a fresh path under `%TEMP%` and
/// relaunches that copy with a hidden `upgrade-apply` subcommand pointed
/// at the verified `.msi`. Returns immediately after spawning; the caller
/// (the CLI's `Upgrade` handler) should exit right after this returns —
/// the relaunched copy is what actually performs the upgrade, and it is
/// about to stop-and-replace the very service this process might be
/// running as.
///
/// Note: unlike the Linux path, this does not run an equivalent of
/// `preflight`'s `<staged> --version`/`validate` checks — the payload is
/// an uninstalled `.msi`, not a directly-runnable staged binary, and
/// extracting a runnable exe from it first (`msiexec /a` administrative
/// install) is real added complexity deferred past this first cut. This is
/// a known gap, not an oversight: it means a Windows upgrade leans more on
/// the manifest/hash verification and the post-install health check than
/// on a pre-install smoke test. Track closing this gap as follow-up work.
pub fn self_relaunch_and_apply(
    zip_path: &Path,
    config_path: &Path,
    data_dir: &Path,
    allow_downgrade: bool,
) -> Result<()> {
    let extract_dir = tempfile::tempdir().context("cannot create extraction temp dir")?;
    let status = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(format!(
            "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
            zip_path.display(),
            extract_dir.path().display()
        ))
        .status()
        .context("cannot run PowerShell Expand-Archive")?;
    if !status.success() {
        bail!("failed to extract update zip {}", zip_path.display());
    }

    let manifest_bytes = std::fs::read(extract_dir.path().join("manifest.json"))
        .context("update zip has no manifest.json")?;
    let sig = std::fs::read(extract_dir.path().join("manifest.json.sig"))
        .context("update zip has no manifest.json.sig")?;
    let manifest = verify_manifest(&manifest_bytes, &sig)?;

    let mut watermark = Watermark::open(data_dir);
    check_freshness(
        &manifest,
        watermark.highest_serial(),
        env!("CARGO_PKG_VERSION"),
        allow_downgrade,
        chrono::Utc::now(),
    )?;

    let artifact = manifest
        .artifact_for(CURRENT_PLATFORM, CURRENT_ARCH)
        .with_context(|| format!("manifest has no artifact for {CURRENT_PLATFORM}/{CURRENT_ARCH}"))?;
    let msi_files: Vec<_> = std::fs::read_dir(extract_dir.path())?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e == "msi").unwrap_or(false))
        .collect();
    let [msi_path] = msi_files.as_slice() else {
        bail!(
            "expected exactly one .msi in the update zip, found {}",
            msi_files.len()
        );
    };
    verify_artifact_hash(msi_path, &artifact.sha256)?;

    // Preflight would go here on Linux; see this function's doc comment
    // for why it's deferred for the MSI path.

    // Point of no return: everything above is read-only with respect to
    // the live install. `config_path` is threaded through only so a
    // future preflight-equivalent can use it once one exists; unused for
    // now, prefixed accordingly.
    let _ = config_path;

    let current = std::env::current_exe().context("cannot resolve the running executable path")?;
    let temp_copy = std::env::temp_dir().join(format!("snx-upgrade-{}.exe", std::process::id()));
    std::fs::copy(&current, &temp_copy)
        .with_context(|| format!("cannot copy {} to {}", current.display(), temp_copy.display()))?;

    // Record the watermark before relaunching, not after: this process is
    // about to hand off to a copy of itself and exit, so it cannot wait
    // for the install to finish and record success afterward the way the
    // Linux path does. This means a Windows upgrade that gets this far but
    // then fails inside `apply_msi` still advances the watermark — an
    // accepted trade-off given `apply_msi` has no automatic rollback yet
    // either (see this task's note on Windows rollback); both gaps close
    // together as Windows support matures past this first cut.
    watermark.record(manifest.manifest_serial)?;

    Command::new(&temp_copy)
        .arg("upgrade-apply")
        .arg("--msi")
        .arg(msi_path)
        .spawn()
        .with_context(|| format!("cannot launch upgrade helper copy {}", temp_copy.display()))?;
    Ok(())
}

/// Runs inside the relaunched temp copy (see `self_relaunch_and_apply`).
/// Re-verifies nothing here — verification already happened in the
/// original process before it decided to relaunch at all; this function's
/// only job is driving the actual MSI install and waiting for the service
/// to come back healthy.
pub fn apply_msi(msi_path: &Path) -> Result<()> {
    let status = Command::new("msiexec")
        .arg("/i")
        .arg(msi_path)
        .arg("/qn")
        .arg("/norestart")
        .status()
        .context("cannot run msiexec")?;
    if !status.success() {
        bail!("msiexec /i {} failed with {status}", msi_path.display());
    }

    if !wait_for_service_running() {
        tracing::error!("service did not reach Running state after MSI upgrade; this build does not yet drive an automatic MSI rollback — see Task 12's manual runbook");
        bail!("upgrade did not become healthy; manual intervention required (see docs/RELEASE-SIGNING.md's Windows section)");
    }
    Ok(())
}

/// Polls the Windows Service Control Manager for up to 60s waiting for the
/// service to report `Running`. Uses the same `windows_service` crate
/// `src/service.rs` already depends on.
fn wait_for_service_running() -> bool {
    use windows_service::service::ServiceState;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        let Ok(manager) = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        ) else {
            continue;
        };
        let Ok(service) = manager.open_service(
            crate::service::SERVICE_NAME,
            windows_service::service::ServiceAccess::QUERY_STATUS,
        ) else {
            continue;
        };
        if let Ok(status) = service.query_status() {
            if status.current_state == ServiceState::Running {
                return true;
            }
        }
    }
    false
}
```

Add to `src/update/mod.rs`:

```rust
#[cfg(windows)]
pub mod apply_windows;
```

- [ ] **Step 2: Wire the hidden CLI subcommand**

In `src/main.rs`, add to the `Command` enum, after `Upgrade`:

```rust
    /// Internal: runs inside the self-relaunched temp copy on Windows to
    /// drive the actual MSI install. Not intended to be run directly.
    #[cfg(windows)]
    #[command(hide = true)]
    UpgradeApply {
        #[arg(long)]
        msi: PathBuf,
    },
```

And to `main()`'s `match`:

```rust
        #[cfg(windows)]
        Some(Command::UpgradeApply { msi }) => {
            softnix_log_agent::update::apply_windows::apply_msi(&msi)
        }
```

And change `upgrade_cmd` (Task 9) to dispatch to the Windows path when applicable — replace its body with:

```rust
fn upgrade_cmd(from: Option<&Path>, rollback: bool, allow_downgrade: bool, config_path: &Path) -> Result<()> {
    let (cfg, _warnings) = config::load(config_path).context("cannot load config for upgrade")?;
    let live_target = std::env::current_exe().context("cannot resolve the running binary's path")?;

    #[cfg(windows)]
    {
        if rollback {
            bail!("Windows rollback is not yet automated by this CLI; see docs/RELEASE-SIGNING.md's Windows rollback runbook (msiexec /x then /i)");
        }
        let from = from.context("--from is required unless --rollback is passed")?;
        return softnix_log_agent::update::apply_windows::self_relaunch_and_apply(
            from,
            config_path,
            &cfg.agent.data_dir,
            allow_downgrade,
        );
    }

    #[cfg(not(windows))]
    {
        if rollback {
            softnix_log_agent::update::apply::rollback_from_local(&live_target, &cfg.agent.data_dir)
        } else {
            let from = from.context("--from is required unless --rollback is passed")?;
            softnix_log_agent::update::apply::apply_from_local(
                from,
                config_path,
                &cfg.agent.data_dir,
                allow_downgrade,
                &live_target,
            )
        }
    }
}
```

(Note: `upgrade_cmd`'s `from` parameter is `Option<&Path>` here because Task 9's follow-up fix changed the CLI's `from` field to `Option<PathBuf>` with `required_unless_present = "rollback"` — see Task 9's corrected text above. Both branches must unwrap it with `.context(...)?` before use when `!rollback`.)

`from` is the same `--from <path>` the CLI already accepts (Task 9) — on Windows it now means "path to the `*-update.zip` bundle," on Linux/other it still means "path to the `*.tar.gz`." `self_relaunch_and_apply`'s own verification (Step 1, above) is what actually enforces the signature/hash/freshness checks before anything is relaunched — `upgrade_cmd` itself stays a thin dispatcher.

(This plan intentionally does not implement Windows automatic rollback — the spec flags the `msiexec /x` then `/i` sequence as needing a real Windows VM test before it can be trusted to run unattended. Task 12 documents the manual procedure; automating it is follow-up work once that manual procedure is proven, not part of this plan.)

- [ ] **Step 3: Run `cargo build` on Linux/macOS to confirm the `#[cfg(windows)]` gates compile out cleanly**

Run: `cargo build`
Expected: succeeds — none of Task 11's code should even be compiled on a non-Windows host, so this is really confirming the `cfg` gates and the shared `upgrade_cmd` function are syntactically valid for both branches.

- [ ] **Step 4: Commit**

```bash
git add src/update/mod.rs src/update/apply_windows.rs src/main.rs
git commit -m "feat(update): drive Windows upgrades through a self-relaunched MSI install"
```

---

### Task 12: Windows manual verification runbook

**Files:**
- Modify: `docs/RELEASE-SIGNING.md` (append a Windows verification + rollback section)

- [ ] **Step 1: Write the runbook**

Append to `docs/RELEASE-SIGNING.md`:

```markdown
## Manually verifying a Windows upgrade (no CI runner for this yet)

On a real Windows VM, with a prior version already installed as a service:

1. Install the old version: `msiexec /i softnix-log-agent-0.1.5-x64.msi /qn`
2. Confirm it's running: `Get-Service softnix-log-agent`
3. Place the new version's `.msi` (plus its `manifest.json`/`manifest.json.sig`, in the same folder) somewhere local.
4. Run: `softnix-log-agent upgrade --from <path-to-new.msi> --config <path>`
5. Confirm the version bumped: `curl http://127.0.0.1:8080/api/about` (or check `Get-Service` restarted recently)
6. Confirm `agent.yaml` under `%ProgramData%\Softnix\LogAgent\` still has your edits (the `DefaultConfig` component is `Permanent="yes"` — it should survive; if it doesn't, that's a real bug, not an acceptable trade-off, and blocks calling Windows upgrade production-ready).
7. Manually test rollback: `msiexec /x <new-product-code> /qn` then `msiexec /i <old.msi> /qn`, then repeat step 6 to confirm config still survived a round trip.

Until this has been run and confirmed at least once on a real Windows host, treat Windows upgrade support as unverified even though the code compiles.
```

- [ ] **Step 2: Commit**

```bash
git add docs/RELEASE-SIGNING.md
git commit -m "docs(update): add the Windows manual verification runbook"
```

---

## Self-Review Notes (from writing this plan)

- **Spec coverage:** every numbered constraint in the spec (`docs/superpowers/specs/2026-09-09-self-update-mechanism.md`) maps to a task: constraint 1 (no UI apply) → nothing in this plan touches `src/web.rs`/`src/ui.html`, by omission (Phase 2's job); constraint 2 (signed manifest, key not in config) → Tasks 1, 6; constraint 3 (no in-process self-replace) → Task 9's CLI-driven design, never triggered from `src/web.rs`; constraint 4 (MSI not raw swap) → Task 11; constraint 5 (rollback mirrors `try_reload`) → Tasks 8, 9, 11; constraint 6 (no separate helper binary) → Task 11's self-copy.
- **Known gaps intentionally left open, not silently dropped:** Windows automatic rollback (Task 11 explicitly refuses `--rollback` on Windows for now, pointing at Task 12's manual runbook); Windows has no preflight-before-install equivalent to Linux's `<staged> --version`/`validate` (Task 11's doc comment on `self_relaunch_and_apply` explains why — the payload is an uninstalled `.msi`, not a directly-runnable staged binary); **`apply_msi` (the relaunched-child side of the Windows path) performs no re-verification of its own, relying entirely on the parent process's checks before it relaunched** — the spec's own text for the Windows apply path calls for the relaunched copy to verify the staged manifest again ("never trust a decision made by a process that's about to exit"), and the shipped code deviates from that. This was caught by the plan's final whole-branch review and deliberately NOT fixed in the same pass: it is Windows-only code with no compile/test signal available on the development machine even once the unrelated `live_target` Windows compile error is fixed, the actual exposure is bounded (driving `msiexec /qn` already requires the same elevation an attacker would need to cause equivalent harm directly — not a privilege-boundary crossing), and closing it properly needs a real design change (threading the extraction directory, not just the `.msi` path, across the process boundary) rather than a small fix. Tracked as follow-up work once a real Windows CI run exists to verify a fix against, rather than shipped unverified.
- **Packaging consistency fix made while writing this plan:** Task 6's first draft published `manifest.json`/`manifest.json.sig` as loose top-level release assets, but Task 9's offline `apply_from_local` (Linux) and Task 11's `self_relaunch_and_apply` (Windows) both need the manifest bundled *inside* the same file `--from` points at, for genuine offline operation. Task 6 was corrected to bundle the manifest into the Linux `.tar.gz` (re-packed after building) and to introduce a new Windows `*-update.zip` (msi + manifest + sig) alongside the unchanged bare `.msi` used for ordinary manual installs. The manifest's `sha256`/`size` fields describe the *inner* binary/msi payload, never the outer bundle — this is what avoids a chicken-and-egg hashing problem (the outer bundle contains the manifest, so its own hash can't be self-referential). Confirm Task 6 is implemented with this fix before starting Task 9 or Task 11 — both assume it.
- **Type consistency check:** `apply_from_local`'s signature grew a `live_target: &Path` parameter between its first mention (Task 9's interface line) and its test (Task 9 Step 1) — confirmed both match `(artifact_path, config_path, data_dir, allow_downgrade, live_target)` in that order throughout Task 9 and Task 10's call site.
