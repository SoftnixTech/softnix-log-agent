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

/// Quotes `path` for embedding inside a PowerShell single-quoted string
/// literal. Windows paths may legitimately contain a `'` (e.g.
/// `C:\Users\O'Brien\...`), and a single-quoted PowerShell string does no
/// interpolation/escape processing at all except that a literal `'` must be
/// doubled — so doubling every `'` is both necessary for such a path to
/// parse correctly and sufficient to stop an embedded quote from closing
/// the string early and letting anything after it run as additional
/// PowerShell. (`"` cannot appear in a Windows path at all, so there is no
/// equivalent concern for the outer process-argument quoting `Command`
/// itself performs.)
fn powershell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

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
    // `Watermark::open` (unlike `StateManager::open`) does not create
    // `data_dir` for us, and `Watermark::record` below needs it to already
    // exist (it writes via `write_atomic`, which requires its target's
    // parent directory to be present) — same gotcha `apply_from_local`
    // documents and handles on Linux. Do it here so a fresh install (agent
    // never previously run, no data dir yet) doesn't fail the very first
    // time someone runs `upgrade` on Windows.
    std::fs::create_dir_all(data_dir)
        .with_context(|| format!("cannot create data directory {}", data_dir.display()))?;

    let extract_dir = tempfile::tempdir().context("cannot create extraction temp dir")?;
    let status = Command::new("powershell")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(format!(
            "Expand-Archive -Path {} -DestinationPath {} -Force",
            powershell_quote(zip_path),
            powershell_quote(extract_dir.path())
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
        .filter(|p| {
            p.extension()
                .map(|e| e.eq_ignore_ascii_case("msi"))
                .unwrap_or(false)
        })
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
