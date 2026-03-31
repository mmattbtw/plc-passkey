import { secp256k1 } from '@noble/curves/secp256k1.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base58btc } from 'multiformats/bases/base58'

const PASSKEY_STORAGE_KEY = 'plc-passkey.credential-id'
const PRF_SALT_STRING = 'did:plc:rotation-key:secp256k1:v1'
const HKDF_INFO = new TextEncoder().encode('did:plc:rotation-key:secp256k1')
const HKDF_SALT = sha256(new TextEncoder().encode('did:plc:rotation-key'))
const SECP256K1_MULTICODEC_PREFIX = new Uint8Array([0xe7, 0x01])

type WebAuthnPrfEval = {
  first: ArrayBuffer
}

type WebAuthnPrfExtensionInput = {
  prf: {
    eval: WebAuthnPrfEval
  }
}

type WebAuthnPrfExtensionOutput = {
  prf?: {
    enabled?: boolean
    results?: {
      first?: ArrayBuffer
    }
  }
}

export type RotationKeypair = {
  credentialId: string
  didKey: string
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export function getStoredCredentialId(): string {
  return localStorage.getItem(PASSKEY_STORAGE_KEY) ?? ''
}

export function storeCredentialId(credentialId: string) {
  localStorage.setItem(PASSKEY_STORAGE_KEY, credentialId)
}

export function clearStoredCredentialId() {
  localStorage.removeItem(PASSKEY_STORAGE_KEY)
}

export function isWebAuthnAvailable() {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window
}

export function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function toBase64Url(bytes: Uint8Array) {
  const base64 = btoa(String.fromCharCode(...bytes))
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '')
}

export function fromBase64Url(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padLength = (4 - (normalized.length % 4)) % 4
  const padded = normalized.padEnd(normalized.length + padLength, '=')
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0))
}

export function signBytesWithRotationKey(privateKey: Uint8Array, bytes: Uint8Array) {
  const signature = secp256k1.sign(bytes, privateKey)
  return toBase64Url(signature)
}

async function getPrfSalt() {
  return crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(PRF_SALT_STRING),
  )
}

function buildPrfExtension(salt: ArrayBuffer): WebAuthnPrfExtensionInput {
  return {
    prf: {
      eval: {
        first: salt,
      },
    },
  }
}

function derivePrivateKey(prfOutput: ArrayBuffer) {
  const ikm = new Uint8Array(prfOutput)

  for (let counter = 0; counter < 256; counter += 1) {
    const info = new Uint8Array([...HKDF_INFO, counter])
    const candidate = hkdf(sha256, ikm, HKDF_SALT, info, 32)

    if (secp256k1.utils.isValidSecretKey(candidate)) {
      return candidate
    }
  }

  throw new Error('Unable to derive a valid secp256k1 secret key from passkey PRF output.')
}

function publicKeyToDidKey(publicKey: Uint8Array) {
  const prefixed = new Uint8Array(SECP256K1_MULTICODEC_PREFIX.length + publicKey.length)
  prefixed.set(SECP256K1_MULTICODEC_PREFIX, 0)
  prefixed.set(publicKey, SECP256K1_MULTICODEC_PREFIX.length)
  return `did:key:${base58btc.encode(prefixed)}`
}

function parsePrfOutput(credential: PublicKeyCredential) {
  const result = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs &
    WebAuthnPrfExtensionOutput

  return result.prf?.results?.first
}

export async function registerRotationPasskey(label: string) {
  if (!isWebAuthnAvailable()) {
    throw new Error('This browser does not support passkeys / WebAuthn.')
  }

  const userId = crypto.getRandomValues(new Uint8Array(16))
  const challenge = crypto.getRandomValues(new Uint8Array(32))
  const salt = await getPrfSalt()

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        name: 'PLC Passkey',
      },
      user: {
        id: userId,
        name: label.trim() || 'plc-passkey-user',
        displayName: label.trim() || 'PLC Passkey User',
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      attestation: 'none',
      timeout: 60_000,
      extensions: buildPrfExtension(salt) as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('Passkey creation was cancelled.')
  }

  const credentialId = toBase64Url(new Uint8Array(credential.rawId))
  storeCredentialId(credentialId)

  return deriveRotationKeyFromPasskey(credentialId)
}

export async function deriveRotationKeyFromPasskey(credentialId: string): Promise<RotationKeypair> {
  if (!credentialId.trim()) {
    throw new Error('A passkey credential ID is required.')
  }

  if (!isWebAuthnAvailable()) {
    throw new Error('This browser does not support passkeys / WebAuthn.')
  }

  const salt = await getPrfSalt()
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: 60_000,
      userVerification: 'required',
      allowCredentials: [
        {
          type: 'public-key',
          id: fromBase64Url(credentialId),
        },
      ],
      extensions: buildPrfExtension(salt) as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null

  if (!assertion) {
    throw new Error('Passkey authentication was cancelled.')
  }

  const prfOutput = parsePrfOutput(assertion)

  if (!prfOutput) {
    throw new Error(
      'This authenticator did not return PRF output. Use a passkey provider with WebAuthn PRF support.',
    )
  }

  const privateKey = derivePrivateKey(prfOutput)
  const publicKey = secp256k1.getPublicKey(privateKey, true)
  const didKey = publicKeyToDidKey(publicKey)

  return {
    credentialId,
    didKey,
    publicKey,
    privateKey,
  }
}

export async function deriveRotationKeyFromAnyPasskey(): Promise<RotationKeypair> {
  if (!isWebAuthnAvailable()) {
    throw new Error('This browser does not support passkeys / WebAuthn.')
  }

  const salt = await getPrfSalt()
  const assertion = (await navigator.credentials.get({
    mediation: 'optional',
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: 60_000,
      userVerification: 'required',
      extensions: buildPrfExtension(salt) as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null

  if (!assertion) {
    throw new Error('Passkey authentication was cancelled.')
  }

  const prfOutput = parsePrfOutput(assertion)

  if (!prfOutput) {
    throw new Error(
      'This authenticator did not return PRF output. Use a passkey provider with WebAuthn PRF support.',
    )
  }

  const credentialId = toBase64Url(new Uint8Array(assertion.rawId))
  storeCredentialId(credentialId)

  const privateKey = derivePrivateKey(prfOutput)
  const publicKey = secp256k1.getPublicKey(privateKey, true)
  const didKey = publicKeyToDidKey(publicKey)

  return {
    credentialId,
    didKey,
    publicKey,
    privateKey,
  }
}
