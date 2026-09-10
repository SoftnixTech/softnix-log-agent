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

## Checking for updates without applying one

`softnix-log-agent upgrade --check` is read-only: it fetches the manifest
and signature from `update.check_url` (see `CONFIGURATION.md`'s `update`
section — the flag requires this to be configured, and does nothing if it
isn't), verifies the signature exactly the way a real `upgrade --from`
would, and prints whether a newer, acceptable version is available. It
never downloads an artifact and never applies anything — applying requires
a separate `upgrade` run, either `--from <downloaded-artifact>` (offline) or
with no `--from` at all (fetches and applies over HTTPS using the same
`check_url`). The same logic backs the web GUI/API's
`GET /api/update/status`, via the shared `update::manifest::evaluate_check`
function, so the CLI and the GUI always agree on whether an update is
available.

## Manually verifying a Windows upgrade (no CI runner for this yet)

On a real Windows VM, with a prior version already installed as a service:

1. Install the old version: `msiexec /i softnix-log-agent-0.1.5-x64.msi /qn`
2. Confirm it's running: `Get-Service softnix-log-agent`
3. Place the new version's `softnix-log-agent-<ver>-windows-x86_64-update.zip` release asset somewhere local — this is the bundle `self_relaunch_and_apply` actually expects (`.msi` + `manifest.json` + `manifest.json.sig` all inside one zip, at the zip's root). A bare `.msi` with loose `manifest.json`/`manifest.json.sig` files next to it does NOT work: `--from`'s very first step is `Expand-Archive` on whatever path it's given, which requires a real zip.
4. Run: `softnix-log-agent upgrade --from <path-to-update.zip> --config <path>`
5. Confirm the version bumped: `curl http://127.0.0.1:8080/api/about` (or check `Get-Service` restarted recently)
6. Confirm `agent.yaml` under `%ProgramData%\Softnix\LogAgent\` still has your edits (the `DefaultConfig` component is `Permanent="yes"` — it should survive; if it doesn't, that's a real bug, not an acceptable trade-off, and blocks calling Windows upgrade production-ready).
7. Manually test rollback: `msiexec /x <new-product-code> /qn` then `msiexec /i <old.msi> /qn`, then repeat step 6 to confirm config still survived a round trip.

Until this has been run and confirmed at least once on a real Windows host, treat Windows upgrade support as unverified even though the code compiles.

## Recovering from a failed Windows install

`self_relaunch_and_apply` (`src/update/apply_windows.rs`) records the
anti-replay watermark *before* spawning the relaunched copy that actually
runs `msiexec` — it hands off to that copy and exits, so unlike the Linux
path it has no way to wait for the install to finish and record the
watermark only on success. If that `msiexec` step then fails (or the
service never comes back to `Running`), the watermark has already
advanced, so re-running `upgrade --from <same zip>` is permanently rejected
as a replay ("manifest_serial is not newer than the last accepted serial")
for that release. `--allow-downgrade` does **not** help here — it only
relaxes the version comparison, not the serial/replay check.

To retry the same release after such a failure: delete (or otherwise reset)
the watermark file the agent's data directory —
`<data_dir>\update-watermark.json` (see `src/update/watermark.rs`;
under the default Windows packaging this is
`C:\ProgramData\Softnix\LogAgent\update-watermark.json`) — before
re-running `upgrade --from` with the same artifact. Confirm the failed
install is actually in a known-good state first (step 7 above) before
retrying.
