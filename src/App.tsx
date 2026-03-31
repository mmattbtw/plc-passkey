import { useEffect, useRef, useState } from 'react'
import './App.css'
import type {
  AtprotoClient,
  RecommendedDidCredentials,
  ResolvedIdentity,
  SavedSession,
} from './lib/atproto'
import type { RotationKeypair } from './lib/passkey'

const SESSION_STORAGE_KEY = 'plc-passkey.session'
const PASSKEY_STORAGE_KEY = 'plc-passkey.credential-id'

type Status = {
  tone: 'idle' | 'success' | 'error'
  message: string
}

function saveSession(saved: SavedSession | null) {
  if (saved) {
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(saved))
    return
  }
  localStorage.removeItem(SESSION_STORAGE_KEY)
}

function readSavedSession(): SavedSession | null {
  const raw = localStorage.getItem(SESSION_STORAGE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as SavedSession
  } catch {
    localStorage.removeItem(SESSION_STORAGE_KEY)
    return null
  }
}

function formatJson(value: unknown) {
  return JSON.stringify(value, null, 2)
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

function getStoredCredentialId() {
  return localStorage.getItem(PASSKEY_STORAGE_KEY) ?? ''
}

function clearStoredCredentialId() {
  localStorage.removeItem(PASSKEY_STORAGE_KEY)
}

function isWebAuthnAvailable() {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window
}

async function loadAtproto() {
  return import('./lib/atproto')
}

async function loadPasskey() {
  return import('./lib/passkey')
}

function App() {
  const agentRef = useRef<AtprotoClient | null>(null)
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [pdsUrl, setPdsUrl] = useState('')
  const [signatureToken, setSignatureToken] = useState('')
  const [passkeyLabel, setPasskeyLabel] = useState('PLC rotation key')
  const [credentialId, setCredentialId] = useState(() => getStoredCredentialId())
  const [identity, setIdentity] = useState<ResolvedIdentity | null>(null)
  const [rotationKeypair, setRotationKeypair] = useState<RotationKeypair | null>(null)
  const [recommended, setRecommended] = useState<RecommendedDidCredentials | null>(null)
  const [loading, setLoading] = useState<string | null>('restore-session')
  const [status, setStatus] = useState<Status>({ tone: 'idle', message: '' })
  const [view, setView] = useState<'home' | 'register' | 'recover'>('home')
  const [registerStep, setRegisterStep] = useState(1)

  useEffect(() => {
    let cancelled = false

    async function restore() {
      const saved = readSavedSession()
      if (!saved) {
        setLoading(null)
        return
      }

      try {
        const { getRecommendedDidCredentials, resumeSavedSession } = await loadAtproto()
        const resumed = await resumeSavedSession(saved)
        if (cancelled) return

        agentRef.current = resumed.client
        saveSession({ pdsUrl: resumed.client.pdsUrl, session: resumed.session })
        setIdentity(resumed.identity)
        setRecommended(await getRecommendedDidCredentials(resumed.client))
        setStatus({
          tone: 'success',
          message: `Restored session for ${resumed.identity.handle}.`,
        })
      } catch (error) {
        const { getErrorMessage } = await loadAtproto()
        if (!cancelled) {
          saveSession(null)
          setStatus({
            tone: 'error',
            message: `Session could not be restored: ${getErrorMessage(error)}`,
          })
        }
      } finally {
        if (!cancelled) setLoading(null)
      }
    }

    void restore()
    return () => { cancelled = true }
  }, [])

  async function handleLogin() {
    setLoading('login')
    setStatus({ tone: 'idle', message: 'Logging in...' })

    try {
      const { getRecommendedDidCredentials, loginWithAtproto } = await loadAtproto()
      const result = await loginWithAtproto({ identifier, password, pdsUrl })

      agentRef.current = result.client
      saveSession({ pdsUrl: result.client.pdsUrl, session: result.session })
      setIdentity(result.identity)
      setRecommended(await getRecommendedDidCredentials(result.client))
      setStatus({
        tone: 'success',
        message: `Logged in as ${result.identity.handle}.`,
      })
      setPassword('')
      setPdsUrl(result.identity.pdsUrl)
      setRegisterStep(2)
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleLogout() {
    agentRef.current = null
    saveSession(null)
    setIdentity(null)
    setRecommended(null)
    setSignatureToken('')
    setView('home')
    setRegisterStep(1)
    setStatus({ tone: 'success', message: 'Session cleared.' })
  }

  async function handleCreatePasskey() {
    setLoading('create-passkey')
    setStatus({ tone: 'idle', message: 'Creating passkey...' })

    try {
      const { registerRotationPasskey } = await loadPasskey()
      const keypair = await registerRotationPasskey(passkeyLabel)
      setCredentialId(keypair.credentialId)
      setRotationKeypair(keypair)
      setStatus({
        tone: 'success',
        message: `Passkey created. Derived ${keypair.didKey}.`,
      })
      setRegisterStep(3)
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleDeriveKey() {
    setLoading('derive-key')
    setStatus({ tone: 'idle', message: 'Deriving key from passkey...' })

    try {
      const { deriveRotationKeyFromPasskey } = await loadPasskey()
      const keypair = await deriveRotationKeyFromPasskey(credentialId)
      setRotationKeypair(keypair)
      setCredentialId(keypair.credentialId)
      setStatus({
        tone: 'success',
        message: `Recovered key material for ${keypair.didKey}.`,
      })
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleDeriveKeyFromAnyPasskey() {
    setLoading('derive-any-key')
    setStatus({
      tone: 'idle',
      message: 'Prompting for any discoverable passkey that can derive this PLC key.',
    })

    try {
      const { deriveRotationKeyFromAnyPasskey } = await loadPasskey()
      const keypair = await deriveRotationKeyFromAnyPasskey()
      setRotationKeypair(keypair)
      setCredentialId(keypair.credentialId)
      setStatus({
        tone: 'success',
        message: `Recovered key material from discoverable passkey for ${keypair.didKey}.`,
      })
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleRequestSignatureToken() {
    if (!agentRef.current) {
      setStatus({ tone: 'error', message: 'Not logged in.' })
      return
    }

    setLoading('request-token')
    setStatus({ tone: 'idle', message: 'Requesting token...' })

    try {
      const { requestPlcOperationSignature } = await loadAtproto()
      await requestPlcOperationSignature(agentRef.current)
      setStatus({
        tone: 'success',
        message: 'Token requested. Check your email if your PDS requires it.',
      })
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleAddRotationKey() {
    if (!agentRef.current || !identity) {
      setStatus({ tone: 'error', message: 'Log in first.' })
      return
    }

    if (!identity.did.startsWith('did:plc:')) {
      setStatus({
        tone: 'error',
        message: `This account uses ${identity.did}, not did:plc.`,
      })
      return
    }

    if (!rotationKeypair) {
      setStatus({ tone: 'error', message: 'Create a passkey first.' })
      return
    }

    setLoading('add-rotation')
    setStatus({ tone: 'idle', message: 'Submitting PLC update...' })

    try {
      const { addRotationKeyFromPasskey, getRecommendedDidCredentials } = await loadAtproto()
      await addRotationKeyFromPasskey({
        client: agentRef.current,
        passkeyDidKey: rotationKeypair.didKey,
        token: signatureToken,
      })

      setRecommended(await getRecommendedDidCredentials(agentRef.current))
      setStatus({
        tone: 'success',
        message: `Done! Rotation keys now include ${rotationKeypair.didKey}.`,
      })
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  function startRegister() {
    setStatus({ tone: 'idle', message: '' })
    setRegisterStep(identity ? 2 : 1)
    setView('register')
  }

  function startRecover() {
    setStatus({ tone: 'idle', message: '' })
    setView('recover')
  }

  function goHome() {
    setStatus({ tone: 'idle', message: '' })
    setView('home')
  }

  const canUseWebAuthn = isWebAuthnAvailable()

  return (
    <main className="app-shell">
      <nav className="top-bar">
        <button className="top-bar-brand" onClick={goHome} type="button">
          <span className="brand-icon">◇</span>
          plc-passkey
        </button>
        <div className="top-bar-meta">
          <span className={`connection-dot ${identity ? 'active' : ''}`} />
          <span className="connection-label">
            {identity ? identity.handle : 'Not connected'}
          </span>
          {identity && (
            <button
              className="nav-link"
              onClick={() => void handleLogout()}
              type="button"
            >
              Log out
            </button>
          )}
        </div>
      </nav>

      <div className="content">
        {status.message && (
          <div className={`status-strip ${status.tone}`}>
            {status.message}
          </div>
        )}

        {view === 'home' && (
          <>
            <header className="hero">
              <div className="hero-label">did:plc × passkey bridge</div>
              <h1>Passkeys as PLC rotation keys.</h1>
              <p className="hero-desc">
                Derive deterministic rotation keys from passkeys and manage
                your <code>did:plc</code> document.
              </p>
            </header>

            <div className="home-actions">
              <button
                className="action-card"
                onClick={startRegister}
                disabled={!canUseWebAuthn || !!loading}
                type="button"
              >
                <div>
                  <h2>Register New Passkey</h2>
                  <p>
                    Log in, create a passkey, and add it as a rotation key to
                    your PLC document.
                  </p>
                </div>
                <span className="action-arrow">→</span>
              </button>

              <button
                className="action-card"
                onClick={startRecover}
                disabled={!canUseWebAuthn || !!loading}
                type="button"
              >
                <div>
                  <h2>Retrieve Secret from Passkey</h2>
                  <p>
                    Re-derive your rotation key material from an existing
                    passkey.
                  </p>
                </div>
                <span className="action-arrow">→</span>
              </button>
            </div>

            <div className="home-badges">
              <span className={`info-badge ${canUseWebAuthn ? 'ok' : 'warn'}`}>
                {canUseWebAuthn
                  ? '✓ WebAuthn available'
                  : '✗ WebAuthn unavailable'}
              </span>
              <span className="info-badge">◇ Keys stay local</span>
            </div>
          </>
        )}

        {view === 'register' && registerStep === 1 && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={goHome} type="button">
                ← Back
              </button>
              <span className="step-indicator">Step 1 of 3</span>
            </div>

            <h2 className="step-title">Log in to your account</h2>
            <p className="step-desc">
              Enter your handle and account password. The app resolves your
              identity through <code>slingshot.microcosm.blue</code> first,
              then uses the returned PDS for the authenticated
              <code> com.atproto.identity.* </code>
              requests.
            </p>

            <div className="fields">
              <div className="field">
                <label htmlFor="identifier">Handle or DID</label>
                <input
                  id="identifier"
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  placeholder="alice.bsky.social or did:plc:..."
                />
              </div>
              <div className="field">
                <label htmlFor="password">Password</label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Account password"
                />
              </div>
            </div>

            <details className="advanced-toggle">
              <summary>Advanced options</summary>
              <div className="field" style={{ marginTop: '0.75rem' }}>
                <label htmlFor="pds-url">PDS URL Override</label>
                <input
                  id="pds-url"
                  value={pdsUrl}
                  onChange={(e) => setPdsUrl(e.target.value)}
                  placeholder="Leave blank to auto-resolve"
                />
                <span className="field-help">
                  Leave blank to resolve through
                  <code> slingshot.microcosm.blue </code>
                  instead of providing the PDS URL manually.
                </span>
              </div>
            </details>

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleLogin()}
                disabled={!!loading || !identifier.trim() || !password}
              >
                {loading === 'login' ? 'Logging In...' : 'Log In'}
              </button>
            </div>
          </section>
        )}

        {view === 'register' && registerStep === 2 && (
          <section className="step-view">
            <div className="step-nav">
              <button
                className="back-btn"
                onClick={() => setRegisterStep(1)}
                type="button"
              >
                ← Back
              </button>
              <span className="step-indicator">Step 2 of 3</span>
            </div>

            <h2 className="step-title">Create a passkey</h2>
            <p className="step-desc">
              This registers a passkey and derives a deterministic rotation key
              from it.
            </p>

            <div className="fields">
              <div className="field">
                <label htmlFor="passkey-label">Passkey Label</label>
                <input
                  id="passkey-label"
                  value={passkeyLabel}
                  onChange={(e) => setPasskeyLabel(e.target.value)}
                  placeholder="PLC rotation key"
                />
              </div>
            </div>

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleCreatePasskey()}
                disabled={!!loading || !canUseWebAuthn}
              >
                {loading === 'create-passkey'
                  ? 'Creating Passkey...'
                  : 'Create Passkey'}
              </button>
            </div>

            {rotationKeypair && (
              <div className="result-block">
                <div className="result-title">Derived Key</div>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">did:key</span>
                    <span className="result-value">
                      {rotationKeypair.didKey}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {view === 'register' && registerStep === 3 && (
          <section className="step-view">
            <div className="step-nav">
              <button
                className="back-btn"
                onClick={() => setRegisterStep(2)}
                type="button"
              >
                ← Back
              </button>
              <span className="step-indicator">Step 3 of 3</span>
            </div>

            <h2 className="step-title">Add rotation key to PLC</h2>
            <p className="step-desc">
              Submit the passkey-backed rotation key to your PLC document.
            </p>

            <div className="fields">
              <div className="field">
                <label htmlFor="signature-token">PLC Signature Token</label>
                <input
                  id="signature-token"
                  value={signatureToken}
                  onChange={(e) => setSignatureToken(e.target.value)}
                  placeholder="Optional — only if your PDS requires one"
                />
              </div>
            </div>

            <div className="button-row">
              <button
                className="button secondary"
                onClick={() => void handleRequestSignatureToken()}
                disabled={!!loading || !identity}
              >
                {loading === 'request-token'
                  ? 'Requesting...'
                  : 'Request Token'}
              </button>
              <button
                className="button"
                onClick={() => void handleAddRotationKey()}
                disabled={!!loading || !identity || !rotationKeypair}
              >
                {loading === 'add-rotation'
                  ? 'Submitting...'
                  : 'Add Rotation Key'}
              </button>
            </div>

            {recommended && (
              <details className="details-block">
                <summary>Current PLC Shape</summary>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">Rotation Keys</span>
                    <pre className="mono-block">
                      {formatJson(recommended.rotationKeys)}
                    </pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Verification Methods</span>
                    <pre className="mono-block">
                      {formatJson(recommended.verificationMethods)}
                    </pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Services</span>
                    <pre className="mono-block">
                      {formatJson(recommended.services)}
                    </pre>
                  </div>
                </div>
              </details>
            )}
          </section>
        )}

        {view === 'recover' && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={goHome} type="button">
                ← Back
              </button>
            </div>

            <h2 className="step-title">Retrieve secret from passkey</h2>
            <p className="step-desc">
              Re-derive your rotation key material from an existing passkey.
              Start with any discoverable passkey on this device. If that does
              not work, fall back to a specific credential ID.
            </p>

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleDeriveKeyFromAnyPasskey()}
                disabled={!!loading || !canUseWebAuthn}
              >
                {loading === 'derive-any-key'
                  ? 'Prompting...'
                  : 'Use Any Available Passkey'}
              </button>
            </div>

            <details className="details-block">
              <summary>Fallback: recover with a credential ID</summary>
              <div className="fields" style={{ marginTop: '1rem' }}>
                <div className="field">
                  <label htmlFor="credential-id">Credential ID</label>
                  <input
                    id="credential-id"
                    value={credentialId}
                    onChange={(e) => setCredentialId(e.target.value)}
                    placeholder="Base64url-encoded credential ID"
                  />
                  <div className="small-actions">
                    <button
                      className="small-button"
                      onClick={() => setCredentialId(getStoredCredentialId())}
                      disabled={!!loading}
                      type="button"
                    >
                      Load stored
                    </button>
                    <button
                      className="small-button"
                      onClick={() => {
                        clearStoredCredentialId()
                        setCredentialId('')
                      }}
                      disabled={!!loading}
                      type="button"
                    >
                      Forget stored
                    </button>
                  </div>
                </div>
              </div>

              <div className="button-row">
                <button
                  className="button secondary"
                  onClick={() => void handleDeriveKey()}
                  disabled={!!loading || !credentialId.trim() || !canUseWebAuthn}
                >
                  {loading === 'derive-key' ? 'Deriving...' : 'Use Credential ID'}
                </button>
              </div>
            </details>

            {rotationKeypair && (
              <div className="result-block">
                <div className="result-title">Derived Rotation Key</div>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">Credential ID</span>
                    <span className="result-value">
                      {rotationKeypair.credentialId}
                    </span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">did:key</span>
                    <span className="result-value">
                      {rotationKeypair.didKey}
                    </span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Secret Key (hex)</span>
                    <div className="mono-block">
                      {bytesToHex(rotationKeypair.privateKey)}
                    </div>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Public Key (hex)</span>
                    <div className="mono-block">
                      {bytesToHex(rotationKeypair.publicKey)}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}
      </div>

      <footer className="app-footer">
        <span>plc-passkey</span>
        <span className="footer-sep">·</span>
        <span>Keys never leave your browser</span>
      </footer>
    </main>
  )
}

export default App
