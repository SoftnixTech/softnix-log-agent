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
