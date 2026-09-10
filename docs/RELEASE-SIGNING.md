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
