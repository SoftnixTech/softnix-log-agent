# Self-update mechanism — design spec

Status: approved by the project owner on 2026-09-09, after two independent
architecture reviews (an internal deep-reasoning pass and a second-opinion
pass from a separate model lineage) converged on the same shape without
seeing each other's answers. This document is the settled design; the
companion plan document implements Phase 0 + Phase 1 of it.

## Goal

Let the agent be upgraded in place — triggered by a human running
`softnix-log-agent upgrade`, or by a fleet-management tool invoking that same
command — without weakening the trust model of a privileged, often
root/LocalSystem background service.

## Hard constraints (non-negotiable, both reviews independently insisted on these)

1. **The web UI never triggers an apply.** It may only report "a newer
   version is available" (Phase 2+). The existing web auth is a single
   static Bearer token with no MFA/step-up (`src/web.rs`) — turning that
   token into a trigger for installing and executing a new privileged
   binary converts a data-exposure risk into remote code execution. CLI
   `upgrade` requires the operator already hold root/Administrator on the
   host, which is the correct authorization level for this action.
2. **A checksum next to the artifact is not authentication.** Whoever
   controls the release host or a TLS-intercepting proxy can regenerate a
   matching checksum for a trojan. Trust is anchored in a signed manifest
   (Ed25519), verified against a public key compiled into the binary —
   never read from config, since the existing Bearer token can already
   rewrite config (`POST /api/config/save`).
3. **No in-process self-replace.** The Linux systemd unit ships
   `ProtectSystem=full` (`src/service.rs`), making `/usr/local/bin`
   read-only to the running service. The CLI `upgrade` command runs as a
   plain, unsandboxed root process instead — it is not the service telling
   itself to replace itself.
4. **Windows applies via a real MSI major upgrade, not a raw `.exe` swap.**
   The shipped Rust binary carries no `VERSIONINFO` resource, so MSI's
   unversioned-file bookkeeping (creation-vs-modification timestamp,
   subject to NTFS tunneling) can nondeterministically decide *not* to
   replace a self-modified exe on a later install/repair. MSI already owns
   stop/replace/restart and preserves `agent.yaml` (`Permanent="yes"`
   component in the `.wxs`).
5. **Rollback mirrors the existing `try_reload` philosophy**
   (`src/main.rs:350-399`): validate before destroying working state, and
   automatically restore the previous good state if the new one fails to
   come up. At the binary level this means: preflight the staged artifact
   *before* touching anything live, keep exactly one previous version on
   disk, and auto-revert once (never loop) if the new version fails its
   health check within a bounded grace window.
6. **No new attack-surface for a problem `rename()` already solves.** No
   separate updater helper binary is shipped. Where a coordinator outside
   the replaced file is needed (Windows), the running process copies
   *itself* (the same signed binary) to a temp path and relaunches it in a
   hidden internal mode — no second artifact to sign, version, or trust.

## Manifest format

Produced by the release pipeline (Phase 0, out of scope for the
implementation plan — a release-engineering/CI task, not agent code),
consumed by the agent's verification code (in scope, Phase 0's agent-side
half):

```json
{
  "schema_version": 1,
  "product": "softnix-log-agent",
  "version": "0.2.0",
  "manifest_serial": 7,
  "released_at": "2026-09-09T00:00:00Z",
  "expires_at": "2027-09-09T00:00:00Z",
  "min_upgrade_from": "0.1.0",
  "artifacts": [
    {
      "platform": "linux",
      "arch": "x86_64",
      "filename": "softnix-log-agent-0.2.0-linux-x86_64.tar.gz",
      "url": "https://dl.softnix.co.th/softnix-log-agent/0.2.0/softnix-log-agent-0.2.0-linux-x86_64.tar.gz",
      "sha256": "<hex>",
      "size": 4823110
    },
    {
      "platform": "windows",
      "arch": "x86_64",
      "filename": "softnix-log-agent-0.2.0-x64.msi",
      "url": "https://dl.softnix.co.th/softnix-log-agent/0.2.0/softnix-log-agent-0.2.0-x64.msi",
      "sha256": "<hex>",
      "size": 6291456
    }
  ]
}
```

Signed as a detached Ed25519 signature over the exact UTF-8 bytes of
`manifest.json` (not a canonicalized/re-serialized form — verify against
the bytes as received, byte-for-byte). Distributed as
`manifest.json` + `manifest.json.sig` alongside the release artifacts, and
also bundled *inside* each artifact (tarball/MSI) so `--from <local file>`
works fully offline with no network fetch (Phase 1's whole point).

`manifest_serial` is a monotonically increasing integer, independent of
`version`, that exists purely to defeat replay of an old-but-validly-signed
manifest: the agent persists the highest serial it has ever accepted and
rejects anything lower. `expires_at` bounds how long a signed manifest
stays valid, so a captured manifest can't be replayed indefinitely.
`min_upgrade_from` lets a release refuse to apply over a version gap that
skipped a required migration.

## Trust anchor

Ed25519 public key(s), compiled into the binary as
`const RELEASE_PUBLIC_KEYS: &[[u8; 32]]` (an array, not a single key, so
rotation is: ship a build trusting `{old, new}`, wait for the fleet to
update, then ship a build trusting only `{new}`). Verification uses `ring`
(already resolved in `Cargo.lock` at 0.17.14 via `rustls`'s `ring` feature;
Phase 0 promotes it to a direct dependency), specifically
`ring::signature::UnparsedPublicKey` with `ring::signature::ED25519`.

Private key custody and the actual signing step are a release-engineering
runbook, not agent code: generate with
`openssl genpkey -algorithm ed25519`, sign with
`openssl pkeyutl -sign -rawin` (PureEdDSA — no digest choice), keep the
private key in a protected GitHub environment requiring reviewer approval
(or a hardware token/KMS), never in ordinary CI secrets available to every
workflow run. This spec does not include a Rust signing tool — the shipped
binary only ever verifies, never signs.

## Platform mechanics

**Linux apply:** stage the extracted binary in the *same directory* as the
live target (avoids a cross-filesystem `EXDEV` rename failure) → preflight
(below) → hardlink the current live binary aside as
`softnix-log-agent.old-<version>` → single atomic `rename()` of the staged
file onto the live path → `softnix-log-agent service restart` (already
exists, drives `systemctl restart`) → poll `GET /healthz` (already public,
unauthenticated) for 3 consecutive `200`s within a 60s grace window.

**Linux rollback:** on preflight or health-check failure, rename the
`.old-<version>` hardlink back onto the live path and restart once more.
Automatic rollback fires at most once per upgrade attempt — never loops.
A day-2 regression (fails hours after a successful health check) is out of
scope for automatic rollback; `softnix-log-agent upgrade --rollback` is the
manual escape hatch, using whichever `.old-<version>` is retained.

**Windows apply:** copy the *running* `softnix-log-agent.exe` to
`%TEMP%\snx-upgrade-<random>.exe` and relaunch that copy with a hidden
`upgrade-apply` subcommand; the original process exits. The relaunched
temp copy verifies the staged `.msi`'s manifest again (never trust a
decision made by a process that's about to exit), then drives
`msiexec /i <verified.msi> /qn /norestart`, waits for the service to reach
`Running` via the Windows Service Control Manager query API, then polls
`/healthz` the same way as Linux.

**Windows rollback:** `msiexec /x <new-product-code>` then
`msiexec /i <retained-old.msi>`. Config survives via the existing
`Permanent="yes"` `DefaultConfig` component. (Flagged risk, not yet
empirically verified on a real Windows host — call this out explicitly
wherever the plan reaches Windows rollback.)

**Both platforms — preflight before touching anything live:** run the
staged binary out-of-band as `<staged> --version` (proves it can even load
on this host's arch/libc) and `<staged> validate --config <live config
path>` (proves the new version still accepts the running configuration).
Either failing aborts before any rename/install happens.

## Explicitly out of scope for this feature, permanently

UI-triggered apply. A separately shipped updater helper binary. A central
RMM/fleet push server (the manifest format is designed so one *could* be
built later without redesigning this). Delta patching. Canary/staged fleet
rollout. Scheduled or unattended automatic installation (never default-on
for a security collector). All of these were considered and rejected by
both independent reviews for reasons specific to this codebase, not
generic caution — see the task-list discussion this spec was extracted
from if the reasoning needs to be revisited.

## Phasing

- **Phase 0** — signing infrastructure + the agent-side verification module
  + fix the pre-existing bug that already blocks Windows upgrades today
  (`packaging/windows/softnix-log-agent.wxs` hardcodes
  `Version="0.1.0"`, and CI never passes `-dVersion` to `candle.exe`, so
  MSI's `MajorUpgrade` element can never trigger on any release built so
  far). Ships no apply capability at all.
- **Phase 1** — `softnix-log-agent upgrade --from <local artifact>
  [--rollback]`. Fully offline, no network client code at all. This is the
  hard engineering (verify, preflight, platform-specific swap, rollback)
  proven with the network attack surface entirely absent, and it is
  immediately useful on its own to air-gapped/restricted-network
  deployments. **This spec's companion plan covers Phase 0 + Phase 1.**
- **Phase 2** (future, separate plan) — read-only network check: a minimal
  TLS-verifying HTTP client scoped to fetching+verifying a manifest only,
  an opt-in-and-disabled-by-default `update.check_url` config, and a
  read-only UI banner. No apply capability added.
- **Phase 3** (future, separate plan) — `softnix-log-agent upgrade` with no
  `--from`: fetch the verified artifact over the network, then reuse
  Phase 1's apply/rollback verbatim.
