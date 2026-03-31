# plc-passkey

> **This is a proof of concept. Do not trust it with your primary account.**

Use passkeys as PLC rotation keys for AT Protocol accounts. This app derives a deterministic secp256k1 keypair from a passkey via the [WebAuthn PRF extension](https://w3c.github.io/webauthn/#prf-extension) and adds the resulting `did:key` to a `did:plc` document as a rotation key.

## How it works

1. **Authenticate** — Start with OAuth and request `atproto identity:*`, or use password login as a fallback during transition.
2. **Create a passkey** — The app registers a discoverable passkey, requests a PRF output, and derives a secp256k1 keypair using HKDF-SHA256.
3. **Submit to PLC** — The derived `did:key` is added to your `did:plc` document as a rotation key via the PDS.

The derived secret key never leaves the browser. PLC writes use the authenticated session; key recovery is a local-only operation.

### Key derivation

```text
WebAuthn PRF output
  → HKDF-SHA256 (salt = sha256("did:plc:rotation-key"), info = "did:plc:rotation-key:secp256k1")
  → secp256k1 private key
  → compressed public key
  → did:key (multicodec 0xe701 + base58btc)
```

## OAuth

This app uses browser OAuth through `@atproto/oauth-client-browser`.

Required scope:

```text
atproto identity:*
```

Why `identity:*`:

- `atproto` is required for atproto OAuth sessions in general.
- `identity:*` is required for PLC DID document changes such as adding rotation keys.
- `identity:handle` alone is not enough for this app because it edits the DID document, not just the handle.

### Development

On loopback hosts (`127.0.0.1`, `[::1]`, or `localhost` redirected to loopback), the app uses the special ATProto localhost OAuth client mode. No hosted metadata document is required for local development.

```bash
bun install
bun run dev
```

### Production

Production needs a hosted OAuth client metadata document at:

```text
https://your-app.example/oauth/client-metadata.json
```

Set `VITE_PUBLIC_URL` before building so Vite emits a matching metadata file:

```bash
VITE_PUBLIC_URL=https://your-app.example bun run build
```

The built app emits `dist/oauth/client-metadata.json`. The deployed site origin must match `VITE_PUBLIC_URL`, or OAuth will fail because the `client_id` and hosted metadata will not match.

## Password fallback

Password login is still present as a fallback during migration.

- App passwords do not work for PLC changes.
- You need the real account password if you use the fallback flow.
- OAuth is the intended default path.

## Requirements

- A browser with WebAuthn support and an authenticator that supports the PRF extension.
- A `did:plc` AT Protocol account if you want to submit PLC updates.

## Build

```bash
bun run build
bun run preview
```

## Storage

The app persists two items in `localStorage`:

| Key | Value |
|---|---|
| `plc-passkey.session` | Saved auth descriptor for OAuth or legacy password session |
| `plc-passkey.credential-id` | Base64url-encoded passkey credential ID |

OAuth browser sessions themselves are managed by the ATProto OAuth client in browser storage.

## Notes

- PRF support is authenticator-dependent. A passkey can exist without supporting PRF.
- Some PDS providers gate PLC operations behind an email confirmation token.
- You can re-derive the same key at any time using the "Retrieve Secret from Passkey" flow. The passkey itself is the backup.
- The default OAuth handle resolver is `https://bsky.social`, matching the browser client examples from the ATProto docs.
