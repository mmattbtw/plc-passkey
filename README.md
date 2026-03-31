# plc-passkey

> **This is a proof of concept. Do not trust it with your primary account.**

Use passkeys as PLC rotation keys for AT Protocol accounts. This app derives a deterministic secp256k1 keypair from a passkey via the [WebAuthn PRF extension](https://w3c.github.io/webauthn/#prf-extension) and adds the resulting `did:key` to a `did:plc` document as a rotation key.

## How it works

1. **Log in** — Authenticate with your handle/DID and your account password.
2. **Create a passkey** — The app registers a discoverable passkey, requests a PRF output, and derives a secp256k1 keypair using HKDF-SHA256.
3. **Submit to PLC** — The derived `did:key` is added to your `did:plc` document as a rotation key via the PDS.

The derived secret key never leaves the browser. PLC writes use the authenticated session; key recovery is a local-only operation.

### Key derivation

```
WebAuthn PRF output
  → HKDF-SHA256 (salt = sha256("did:plc:rotation-key"), info = "did:plc:rotation-key:secp256k1")
  → secp256k1 private key
  → compressed public key
  → did:key (multicodec 0xe701 + base58btc)
```

## Requirements

- A browser with WebAuthn support and an authenticator that supports the PRF extension.
- A `did:plc` AT Protocol account (app passwords won't work — your real account password is required).

## Development

```bash
bun install
bun run dev
```

## Build

```bash
bun run build
bun run preview
```

## Storage

The app persists two items in `localStorage`:

| Key | Value |
|---|---|
| `plc-passkey.session` | ATProto session bundle (access/refresh JWTs) |
| `plc-passkey.credential-id` | Base64url-encoded passkey credential ID |

## Notes

- PRF support is authenticator-dependent. A passkey can exist without supporting PRF.
- Some PDS providers gate PLC operations behind an email confirmation token.
- You can re-derive the same key at any time using the "Retrieve Secret from Passkey" flow — the passkey itself is the backup.
