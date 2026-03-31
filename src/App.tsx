import { useEffect, useRef, useState } from 'react'
import './App.css'
import type {
  AtprotoClient,
  PlcAuditEntry,
  PlcData,
  PlcSignedOperation,
  PlcUnsignedOperation,
  RecommendedDidCredentials,
  ResolvedIdentity,
  SavedSession,
} from './lib/atproto'
import type { RotationKeypair } from './lib/passkey'

const SESSION_STORAGE_KEY = 'plc-passkey.session'
const PASSKEY_STORAGE_KEY = 'plc-passkey.credential-id'
const AUTH_INTENT_STORAGE_KEY = 'plc-passkey.auth-intent'

type Status = {
  tone: 'idle' | 'success' | 'error'
  message: string
}

type AuthIntent = {
  view: 'register'
  registerStep: 2
}

type View = 'home' | 'register' | 'recover' | 'edit-plc'
type PlcEditorMode = 'safe' | 'raw'

type SafePlcDraft = {
  alsoKnownAsText: string
  rotationKeysText: string
  pdsEndpoint: string
  extraServicesJson: string
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

function saveAuthIntent(intent: AuthIntent | null) {
  if (intent) {
    localStorage.setItem(AUTH_INTENT_STORAGE_KEY, JSON.stringify(intent))
    return
  }

  localStorage.removeItem(AUTH_INTENT_STORAGE_KEY)
}

function readAuthIntent(): AuthIntent | null {
  const raw = localStorage.getItem(AUTH_INTENT_STORAGE_KEY)
  if (!raw) return null

  try {
    const parsed = JSON.parse(raw) as Partial<AuthIntent>
    if (parsed.view === 'register' && parsed.registerStep === 2) {
      return { view: 'register', registerStep: 2 }
    }
  } catch {
    // Ignore parse failures and clear below.
  }

  localStorage.removeItem(AUTH_INTENT_STORAGE_KEY)
  return null
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function parseLineList(value: string) {
  return value
    .split('\n')
    .map((entry) => entry.trim())
    .filter(Boolean)
}

function formatLineList(values: string[]) {
  return values.join('\n')
}

function createSafePlcDraft(plcData: PlcData): SafePlcDraft {
  const services = { ...plcData.services }
  const atprotoPds = isRecord(services.atproto_pds) ? services.atproto_pds : null

  if ('atproto_pds' in services) {
    delete services.atproto_pds
  }

  const endpoint =
    atprotoPds && typeof atprotoPds.endpoint === 'string' ? atprotoPds.endpoint : ''

  return {
    alsoKnownAsText: formatLineList(plcData.alsoKnownAs),
    rotationKeysText: formatLineList(plcData.rotationKeys),
    pdsEndpoint: endpoint,
    extraServicesJson: formatJson(services),
  }
}

function createUnsignedOperationFromPlc(
  plcData: PlcData,
  prev: string | null,
): PlcUnsignedOperation {
  return {
    type: 'plc_operation',
    prev,
    rotationKeys: plcData.rotationKeys,
    alsoKnownAs: plcData.alsoKnownAs,
    verificationMethods: plcData.verificationMethods,
    services: plcData.services,
  }
}

function parseJsonObject(label: string, value: string) {
  try {
    const parsed = JSON.parse(value) as unknown
    if (!isRecord(parsed)) {
      throw new Error(`${label} must be a JSON object.`)
    }
    return parsed
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`${label}: ${error.message}`)
    }
    throw new Error(`${label} is invalid.`)
  }
}

function buildSafeUnsignedOperation(params: {
  plcData: PlcData
  prev: string
  draft: SafePlcDraft
}): PlcUnsignedOperation {
  const rotationKeys = parseLineList(params.draft.rotationKeysText)
  const alsoKnownAs = parseLineList(params.draft.alsoKnownAsText)

  if (!rotationKeys.length) {
    throw new Error('At least one rotation key is required.')
  }

  const extraServices = parseJsonObject(
    'Additional services JSON',
    params.draft.extraServicesJson || '{}',
  )

  const existingPds = isRecord(params.plcData.services.atproto_pds)
    ? params.plcData.services.atproto_pds
    : null
  const services = { ...extraServices }
  const endpoint = params.draft.pdsEndpoint.trim()

  if (endpoint) {
    services.atproto_pds = {
      ...(existingPds ?? {}),
      type:
        existingPds && typeof existingPds.type === 'string'
          ? existingPds.type
          : 'AtprotoPersonalDataServer',
      endpoint,
    }
  } else if (existingPds) {
    throw new Error('PDS endpoint cannot be blank in safe mode.')
  }

  return {
    type: 'plc_operation',
    prev: params.prev,
    rotationKeys,
    alsoKnownAs,
    verificationMethods: params.plcData.verificationMethods,
    services,
  }
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
  const [view, setView] = useState<View>('home')
  const [registerStep, setRegisterStep] = useState(1)
  const [plcIdentifier, setPlcIdentifier] = useState('')
  const [plcStep, setPlcStep] = useState(1)
  const [plcIdentity, setPlcIdentity] = useState<ResolvedIdentity | null>(null)
  const [plcData, setPlcData] = useState<PlcData | null>(null)
  const [plcAuditEntry, setPlcAuditEntry] = useState<PlcAuditEntry | null>(null)
  const [plcEditorMode, setPlcEditorMode] = useState<PlcEditorMode>('safe')
  const [plcSafeDraft, setPlcSafeDraft] = useState<SafePlcDraft>({
    alsoKnownAsText: '',
    rotationKeysText: '',
    pdsEndpoint: '',
    extraServicesJson: '{}',
  })
  const [plcRawDraft, setPlcRawDraft] = useState('')
  const [plcKeypair, setPlcKeypair] = useState<RotationKeypair | null>(null)
  const [plcSubmittedOperation, setPlcSubmittedOperation] = useState<PlcSignedOperation | null>(null)

  useEffect(() => {
    let cancelled = false

    function applyAuthIntent(restoredFromCallback: boolean) {
      if (!restoredFromCallback) {
        return
      }

      const intent = readAuthIntent()
      saveAuthIntent(null)

      if (intent?.view === 'register') {
        setView('register')
        setRegisterStep(intent.registerStep)
      }
    }

    async function restore() {
      const saved = readSavedSession()
      if (!saved) {
        try {
          const { getRecommendedDidCredentials, restorePreviousSession } = await loadAtproto()
          const restored = await restorePreviousSession(null)

          if (cancelled) return
          if (!restored) {
            setLoading(null)
            return
          }

          agentRef.current = restored.client
          saveSession(restored.saved)
          setIdentity(restored.identity)
          setRecommended(await getRecommendedDidCredentials(restored.client))
          setPdsUrl(restored.identity.pdsUrl)
          applyAuthIntent(restored.restoredFromCallback)
          setStatus({
            tone: 'success',
            message: restored.restoredFromCallback
              ? `Authenticated via OAuth as ${restored.identity.handle}.`
              : `Restored session for ${restored.identity.handle}.`,
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

        return
      }

      try {
        const {
          getRecommendedDidCredentials,
          normalizeSavedSession,
          restorePreviousSession,
        } = await loadAtproto()
        const normalized = normalizeSavedSession(saved)
        const resumed = await restorePreviousSession(normalized)
        if (cancelled) return

        if (!resumed) {
          saveSession(null)
          setLoading(null)
          return
        }

        agentRef.current = resumed.client
        saveSession(resumed.saved)
        setIdentity(resumed.identity)
        setRecommended(await getRecommendedDidCredentials(resumed.client))
        setPdsUrl(resumed.identity.pdsUrl)
        applyAuthIntent(resumed.restoredFromCallback)
        setStatus({
          tone: 'success',
          message: resumed.restoredFromCallback
            ? `Authenticated via OAuth as ${resumed.identity.handle}.`
            : `Restored session for ${resumed.identity.handle}.`,
        })
      } catch (error) {
        const { getErrorMessage } = await loadAtproto()
        if (!cancelled) {
          saveSession(null)
          setStatus({ tone: 'error', message: `Session could not be restored: ${getErrorMessage(error)}` })
        }
      } finally {
        if (!cancelled) setLoading(null)
      }
    }

    void restore()
    return () => {
      cancelled = true
    }
  }, [])

  async function handleOAuthLogin() {
    if (!identifier.trim()) {
      setStatus({ tone: 'error', message: 'Enter a handle or DID first.' })
      return
    }

    setLoading('oauth-login')
    setStatus({ tone: 'idle', message: 'Redirecting to OAuth login...' })
    saveAuthIntent({ view: 'register', registerStep: 2 })

    try {
      const { beginOAuthLogin } = await loadAtproto()
      await beginOAuthLogin(identifier)
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      saveAuthIntent(null)
      setStatus({ tone: 'error', message: getErrorMessage(error) })
      setLoading(null)
    }
  }

  async function handleLogin() {
    setLoading('login')
    setStatus({ tone: 'idle', message: 'Logging in...' })

    try {
      const {
        getRecommendedDidCredentials,
        getSavedSessionForClient,
        loginWithAtproto,
      } = await loadAtproto()
      const result = await loginWithAtproto({ identifier, password, pdsUrl })

      agentRef.current = result.client
      saveSession(getSavedSessionForClient(result.client))
      setIdentity(result.identity)
      setRecommended(await getRecommendedDidCredentials(result.client))
      setStatus({
        tone: 'success',
        message: `Logged in with password as ${result.identity.handle}.`,
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
    const client = agentRef.current

    try {
      if (client) {
        const { logoutClient } = await loadAtproto()
        await logoutClient(client)
      }
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
      return
    }

    agentRef.current = null
    saveSession(null)
    saveAuthIntent(null)
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
      if (view === 'register') {
        setRegisterStep(3)
      }
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
      if (view === 'register') {
        setRegisterStep(3)
      }
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
      if (view === 'register') {
        setRegisterStep(3)
      }
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleRequestSignatureToken() {
    if (!agentRef.current || !identity) {
      setStatus({ tone: 'error', message: 'Not logged in.' })
      return
    }

    if (!identity.did.startsWith('did:plc:')) {
      setStatus({
        tone: 'error',
        message: `This account uses ${identity.did}, not did:plc.`,
      })
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

  function resetDirectPlcEditor() {
    setPlcStep(1)
    setPlcIdentity(null)
    setPlcData(null)
    setPlcAuditEntry(null)
    setPlcEditorMode('safe')
    setPlcSafeDraft({
      alsoKnownAsText: '',
      rotationKeysText: '',
      pdsEndpoint: '',
      extraServicesJson: '{}',
    })
    setPlcRawDraft('')
    setPlcKeypair(null)
    setPlcSubmittedOperation(null)
  }

  async function handleLoadPlcDocument() {
    if (!plcIdentifier.trim()) {
      setStatus({ tone: 'error', message: 'Enter a handle or DID first.' })
      return
    }

    setLoading('load-plc')
    setStatus({ tone: 'idle', message: 'Resolving identity and loading PLC document...' })

    try {
      const { getCurrentPlcData, getLatestValidAuditEntry, getPlcAuditLog, resolveIdentity } =
        await loadAtproto()
      const resolved = await resolveIdentity(plcIdentifier)

      if (!resolved.did.startsWith('did:plc:')) {
        throw new Error(`This account uses ${resolved.did}, not did:plc.`)
      }

      const current = await getCurrentPlcData(resolved.did)
      const auditEntries = await getPlcAuditLog(resolved.did)
      const latestAuditEntry = getLatestValidAuditEntry(auditEntries)
      const initialOperation = createUnsignedOperationFromPlc(current, latestAuditEntry.cid)

      setPlcIdentity(resolved)
      setPlcData(current)
      setPlcAuditEntry(latestAuditEntry)
      setPlcSafeDraft(createSafePlcDraft(current))
      setPlcRawDraft(formatJson(initialOperation))
      setPlcEditorMode('safe')
      setPlcKeypair(null)
      setPlcSubmittedOperation(null)
      setPlcStep(2)
      setStatus({
        tone: 'success',
        message: `Loaded current PLC state for ${resolved.handle}. Authenticate with a passkey that is already a rotation key.`,
      })
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function completePlcPasskeyAuth(keypair: RotationKeypair) {
    if (!plcData) {
      throw new Error('Load a PLC document first.')
    }

    if (!plcData.rotationKeys.includes(keypair.didKey)) {
      throw new Error(
        `This passkey derives ${keypair.didKey}, which is not a current PLC rotation key. Bootstrap it with the Add Passkey flow first.`,
      )
    }

    setPlcKeypair(keypair)
    setCredentialId(keypair.credentialId)
    setPlcStep(3)
    setStatus({
      tone: 'success',
      message: `Authenticated as PLC rotation key ${keypair.didKey}. You can now edit and submit the document directly to plc.directory.`,
    })
  }

  async function handleUseAnyPlcPasskey() {
    setLoading('plc-passkey-any')
    setStatus({ tone: 'idle', message: 'Prompting for an existing passkey...' })

    try {
      const { deriveRotationKeyFromAnyPasskey } = await loadPasskey()
      const keypair = await deriveRotationKeyFromAnyPasskey()
      await completePlcPasskeyAuth(keypair)
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  async function handleUseSpecificPlcPasskey() {
    setLoading('plc-passkey-specific')
    setStatus({ tone: 'idle', message: 'Authenticating with the stored credential ID...' })

    try {
      const { deriveRotationKeyFromPasskey } = await loadPasskey()
      const keypair = await deriveRotationKeyFromPasskey(credentialId)
      await completePlcPasskeyAuth(keypair)
    } catch (error) {
      const { getErrorMessage } = await loadAtproto()
      setStatus({ tone: 'error', message: getErrorMessage(error) })
    } finally {
      setLoading(null)
    }
  }

  function syncRawDraftFromSafe() {
    if (!plcData || !plcAuditEntry) {
      setStatus({ tone: 'error', message: 'Load a PLC document first.' })
      return
    }

    try {
      const unsigned = buildSafeUnsignedOperation({
        plcData,
        prev: plcAuditEntry.cid,
        draft: plcSafeDraft,
      })
      setPlcRawDraft(formatJson(unsigned))
      setStatus({
        tone: 'success',
        message: 'Raw editor refreshed from the current safe-mode fields.',
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      setStatus({ tone: 'error', message })
    }
  }

  async function handleSubmitDirectPlc() {
    if (!plcIdentity || !plcData || !plcAuditEntry || !plcKeypair) {
      setStatus({ tone: 'error', message: 'Load the PLC document and authenticate with a passkey first.' })
      return
    }

    setLoading('submit-direct-plc')
    setStatus({ tone: 'idle', message: 'Signing PLC operation and submitting directly to plc.directory...' })

    try {
      const {
        encodeUnsignedPlcOperation,
        getCurrentPlcData,
        getLatestValidAuditEntry,
        getPlcAuditLog,
        parseRawPlcOperation,
        submitDirectPlcOperation,
      } = await loadAtproto()
      const { signBytesWithRotationKey } = await loadPasskey()

      let unsignedOperation: PlcUnsignedOperation

      if (plcEditorMode === 'safe') {
        unsignedOperation = buildSafeUnsignedOperation({
          plcData,
          prev: plcAuditEntry.cid,
          draft: plcSafeDraft,
        })
      } else {
        unsignedOperation = parseRawPlcOperation(plcRawDraft)
        if (unsignedOperation.prev !== plcAuditEntry.cid) {
          throw new Error('Raw PLC JSON "prev" must match the latest valid audit-log CID.')
        }
      }

      const bytes = encodeUnsignedPlcOperation(unsignedOperation)
      const signature = signBytesWithRotationKey(plcKeypair.privateKey, bytes)
      const signedOperation: PlcSignedOperation = {
        ...unsignedOperation,
        sig: signature,
      }

      await submitDirectPlcOperation(plcIdentity.did, signedOperation)

      const refreshedPlcData = await getCurrentPlcData(plcIdentity.did)
      const refreshedAuditLog = await getPlcAuditLog(plcIdentity.did)
      const refreshedAuditEntry = getLatestValidAuditEntry(refreshedAuditLog)

      setPlcData(refreshedPlcData)
      setPlcAuditEntry(refreshedAuditEntry)
      setPlcSafeDraft(createSafePlcDraft(refreshedPlcData))
      setPlcRawDraft(
        formatJson(createUnsignedOperationFromPlc(refreshedPlcData, refreshedAuditEntry.cid)),
      )
      setPlcSubmittedOperation(signedOperation)
      setStatus({
        tone: 'success',
        message: `PLC operation accepted for ${plcIdentity.handle}. Current document reloaded from plc.directory.`,
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

  function startEditPlc() {
    setStatus({ tone: 'idle', message: '' })
    resetDirectPlcEditor()
    setPlcIdentifier(identity?.handle ?? '')
    setView('edit-plc')
  }

  function goHome() {
    setStatus({ tone: 'idle', message: '' })
    setView('home')
  }

  const canUseWebAuthn = isWebAuthnAvailable()
  const plcSupportError =
    agentRef.current?.auth.kind === 'oauth' &&
    !agentRef.current.auth.grantedScopes.includes('identity:*')
      ? 'This OAuth session is missing identity:*. Re-authenticate and grant atproto identity:*.'
      : null

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
        {status.message && <div className={`status-strip ${status.tone}`}>{status.message}</div>}

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
                onClick={startEditPlc}
                disabled={!canUseWebAuthn || !!loading}
                type="button"
              >
                <div>
                  <h2>Edit PLC Document</h2>
                  <p>
                    Resolve a handle, authenticate with an existing passkey
                    rotation key, then sign and submit updates directly to
                    <code> plc.directory</code>.
                  </p>
                </div>
                <span className="action-arrow">→</span>
              </button>

              <button
                className="action-card"
                onClick={startRegister}
                disabled={!canUseWebAuthn || !!loading}
                type="button"
              >
                <div>
                  <h2>Add Passkey To PLC</h2>
                  <p>
                    Log in, use a new or existing passkey, and add it as a
                    rotation key to your PLC document.
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
                {canUseWebAuthn ? '✓ WebAuthn available' : '✗ WebAuthn unavailable'}
              </span>
              <span className="info-badge">◇ Keys stay local</span>
              <span className="info-badge">◇ Direct PLC signing</span>
            </div>
          </>
        )}

        {view === 'edit-plc' && plcStep === 1 && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={goHome} type="button">
                ← Back
              </button>
              <span className="step-indicator">Step 1 of 3</span>
            </div>

            <h2 className="step-title">Load PLC document</h2>
            <p className="step-desc">
              Enter a handle or DID, resolve it to <code>did:plc</code>, and
              load the current document plus the latest valid audit-log CID
              from <code>plc.directory</code>.
            </p>

            <div className="fields">
              <div className="field">
                <label htmlFor="plc-identifier">Handle or DID</label>
                <input
                  id="plc-identifier"
                  value={plcIdentifier}
                  onChange={(e) => setPlcIdentifier(e.target.value)}
                  placeholder="alice.bsky.social or did:plc:..."
                />
              </div>
            </div>

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleLoadPlcDocument()}
                disabled={!!loading || !plcIdentifier.trim()}
                type="button"
              >
                {loading === 'load-plc' ? 'Loading...' : 'Load PLC Document'}
              </button>
            </div>
          </section>
        )}

        {view === 'edit-plc' && plcStep === 2 && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={() => setPlcStep(1)} type="button">
                ← Back
              </button>
              <span className="step-indicator">Step 2 of 3</span>
            </div>

            <h2 className="step-title">Authenticate with passkey</h2>
            <p className="step-desc">
              Use an existing passkey whose derived <code>did:key</code> is
              already present in the live <code>rotationKeys</code> list.
            </p>

            {plcIdentity && plcData && plcAuditEntry && (
              <div className="result-block">
                <div className="result-title">Loaded PLC State</div>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">Handle</span>
                    <span className="result-value">{plcIdentity.handle}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">DID</span>
                    <span className="result-value">{plcIdentity.did}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Latest Valid CID</span>
                    <span className="result-value">{plcAuditEntry.cid}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Rotation Keys</span>
                    <pre className="mono-block">{formatJson(plcData.rotationKeys)}</pre>
                  </div>
                </div>
              </div>
            )}

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleUseAnyPlcPasskey()}
                disabled={!!loading || !canUseWebAuthn}
                type="button"
              >
                {loading === 'plc-passkey-any' ? 'Prompting...' : 'Use Existing Passkey'}
              </button>
            </div>

            <details className="details-block">
              <summary>Fallback: use a credential ID</summary>
              <div className="fields" style={{ marginTop: '1rem' }}>
                <div className="field">
                  <label htmlFor="credential-id-direct">Credential ID</label>
                  <input
                    id="credential-id-direct"
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
                  onClick={() => void handleUseSpecificPlcPasskey()}
                  disabled={!!loading || !credentialId.trim() || !canUseWebAuthn}
                  type="button"
                >
                  {loading === 'plc-passkey-specific' ? 'Authenticating...' : 'Use Credential ID'}
                </button>
              </div>
            </details>
          </section>
        )}

        {view === 'edit-plc' && plcStep === 3 && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={() => setPlcStep(2)} type="button">
                ← Back
              </button>
              <span className="step-indicator">Step 3 of 3</span>
            </div>

            <h2 className="step-title">Edit and submit PLC operation</h2>
            <p className="step-desc">
              Safe mode keeps <code>verificationMethods</code> read-only. Raw
              mode exposes the full unsigned PLC operation behind a dangerous
              toggle.
            </p>

            {plcIdentity && plcAuditEntry && plcKeypair && (
              <div className="result-block">
                <div className="result-title">Active Signing Context</div>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">Handle</span>
                    <span className="result-value">{plcIdentity.handle}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Signing did:key</span>
                    <span className="result-value">{plcKeypair.didKey}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Prev CID</span>
                    <span className="result-value">{plcAuditEntry.cid}</span>
                  </div>
                </div>
              </div>
            )}

            <div className="editor-toggle-row">
              <button
                className={`toggle-chip ${plcEditorMode === 'safe' ? 'active' : ''}`}
                onClick={() => setPlcEditorMode('safe')}
                type="button"
              >
                Safe Mode
              </button>
              <button
                className={`toggle-chip danger ${plcEditorMode === 'raw' ? 'active' : ''}`}
                onClick={() => setPlcEditorMode('raw')}
                type="button"
              >
                DANGEROUS OPTION
              </button>
            </div>

            {plcEditorMode === 'safe' && plcData && (
              <>
                <div className="fields">
                  <div className="field">
                    <label htmlFor="safe-also-known-as">alsoKnownAs</label>
                    <textarea
                      id="safe-also-known-as"
                      value={plcSafeDraft.alsoKnownAsText}
                      onChange={(e) =>
                        setPlcSafeDraft((current) => ({
                          ...current,
                          alsoKnownAsText: e.target.value,
                        }))
                      }
                      placeholder="One at:// URI per line"
                    />
                  </div>

                  <div className="field">
                    <label htmlFor="safe-rotation-keys">rotationKeys</label>
                    <textarea
                      id="safe-rotation-keys"
                      value={plcSafeDraft.rotationKeysText}
                      onChange={(e) =>
                        setPlcSafeDraft((current) => ({
                          ...current,
                          rotationKeysText: e.target.value,
                        }))
                      }
                      placeholder="One did:key per line"
                    />
                  </div>

                  <div className="field">
                    <label htmlFor="safe-pds-endpoint">services.atproto_pds.endpoint</label>
                    <input
                      id="safe-pds-endpoint"
                      value={plcSafeDraft.pdsEndpoint}
                      onChange={(e) =>
                        setPlcSafeDraft((current) => ({
                          ...current,
                          pdsEndpoint: e.target.value,
                        }))
                      }
                      placeholder="https://your-pds.example"
                    />
                  </div>

                  <div className="field">
                    <label htmlFor="safe-services-json">Additional Services JSON</label>
                    <textarea
                      id="safe-services-json"
                      value={plcSafeDraft.extraServicesJson}
                      onChange={(e) =>
                        setPlcSafeDraft((current) => ({
                          ...current,
                          extraServicesJson: e.target.value,
                        }))
                      }
                      placeholder="{}"
                    />
                    <span className="field-help">
                      Edits the existing <code>services</code> entries other than
                      <code> atproto_pds</code>.
                    </span>
                  </div>
                </div>

                <div className="result-block">
                  <div className="result-title">verificationMethods (read-only)</div>
                  <div className="result-grid">
                    <div className="result-row">
                      <pre className="mono-block">{formatJson(plcData.verificationMethods)}</pre>
                    </div>
                  </div>
                </div>
              </>
            )}

            {plcEditorMode === 'raw' && (
              <div className="fields">
                <div className="field">
                  <label htmlFor="raw-plc-json">Unsigned PLC Operation JSON</label>
                  <textarea
                    id="raw-plc-json"
                    className="code-textarea"
                    value={plcRawDraft}
                    onChange={(e) => setPlcRawDraft(e.target.value)}
                    placeholder={`{\n  "type": "plc_operation"\n}`}
                  />
                </div>
              </div>
            )}

            <div className="button-row">
              {plcEditorMode === 'raw' && (
                <button
                  className="button secondary"
                  onClick={syncRawDraftFromSafe}
                  disabled={!!loading || !plcData || !plcAuditEntry}
                  type="button"
                >
                  Refresh Raw From Safe Fields
                </button>
              )}
              <button
                className="button"
                onClick={() => void handleSubmitDirectPlc()}
                disabled={!!loading || !plcKeypair || !plcAuditEntry}
                type="button"
              >
                {loading === 'submit-direct-plc' ? 'Submitting...' : 'Submit Direct PLC Update'}
              </button>
            </div>

            {plcSubmittedOperation && (
              <details className="details-block">
                <summary>Last Submitted Operation</summary>
                <pre className="mono-block">{formatJson(plcSubmittedOperation)}</pre>
              </details>
            )}

            {plcData && plcAuditEntry && (
              <details className="details-block">
                <summary>Current PLC Shape</summary>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">Latest Valid CID</span>
                    <span className="result-value">{plcAuditEntry.cid}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Rotation Keys</span>
                    <pre className="mono-block">{formatJson(plcData.rotationKeys)}</pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">alsoKnownAs</span>
                    <pre className="mono-block">{formatJson(plcData.alsoKnownAs)}</pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Verification Methods</span>
                    <pre className="mono-block">{formatJson(plcData.verificationMethods)}</pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Services</span>
                    <pre className="mono-block">{formatJson(plcData.services)}</pre>
                  </div>
                </div>
              </details>
            )}
          </section>
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
              OAuth is the default path for PLC updates. Enter your handle or
              DID, then continue with an OAuth session that grants
              <code> atproto identity:* </code>. Password login is still
              available below as a fallback during transition.
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
            </div>

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleOAuthLogin()}
                disabled={!!loading || !identifier.trim()}
                type="button"
              >
                {loading === 'oauth-login' ? 'Redirecting...' : 'Continue With OAuth'}
              </button>
            </div>

            <details className="advanced-toggle">
              <summary>Password fallback</summary>
              <div className="fields" style={{ marginTop: '0.75rem' }}>
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

                <div className="field">
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
              </div>

              <div className="button-row">
                <button
                  className="button secondary"
                  onClick={() => void handleLogin()}
                  disabled={!!loading || !identifier.trim() || !password}
                  type="button"
                >
                  {loading === 'login' ? 'Logging In...' : 'Use Password Instead'}
                </button>
              </div>
            </details>
          </section>
        )}

        {view === 'register' && registerStep === 2 && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={() => setRegisterStep(1)} type="button">
                ← Back
              </button>
              <span className="step-indicator">Step 2 of 3</span>
            </div>

            <h2 className="step-title">Choose a passkey</h2>
            <p className="step-desc">
              You can create a new passkey or use an existing one. Either way,
              the app derives a deterministic rotation key locally before the
              PLC update.
            </p>

            <div className="button-row">
              <button
                className="button"
                onClick={() => void handleDeriveKeyFromAnyPasskey()}
                disabled={!!loading || !canUseWebAuthn}
                type="button"
              >
                {loading === 'derive-any-key' ? 'Prompting...' : 'Use Existing Passkey'}
              </button>
              <button
                className="button secondary"
                onClick={() => void handleCreatePasskey()}
                disabled={!!loading || !canUseWebAuthn}
                type="button"
              >
                {loading === 'create-passkey' ? 'Creating Passkey...' : 'Create New Passkey'}
              </button>
            </div>

            <details className="details-block">
              <summary>Fallback: use a credential ID</summary>
              <div className="fields" style={{ marginTop: '1rem' }}>
                <div className="field">
                  <label htmlFor="credential-id-register">Credential ID</label>
                  <input
                    id="credential-id-register"
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
                  type="button"
                >
                  {loading === 'derive-key' ? 'Deriving...' : 'Use Credential ID'}
                </button>
              </div>
            </details>

            <div className="fields">
              <div className="field">
                <label htmlFor="passkey-label">Passkey Label</label>
                <input
                  id="passkey-label"
                  value={passkeyLabel}
                  onChange={(e) => setPasskeyLabel(e.target.value)}
                  placeholder="PLC rotation key"
                />
                <span className="field-help">Only used when creating a new passkey.</span>
              </div>
            </div>

            {rotationKeypair && (
              <div className="result-block">
                <div className="result-title">Derived Key</div>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">did:key</span>
                    <span className="result-value">{rotationKeypair.didKey}</span>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {view === 'register' && registerStep === 3 && (
          <section className="step-view">
            <div className="step-nav">
              <button className="back-btn" onClick={() => setRegisterStep(2)} type="button">
                ← Back
              </button>
              <span className="step-indicator">Step 3 of 3</span>
            </div>

            <h2 className="step-title">Add rotation key to PLC</h2>
            <p className="step-desc">Submit the passkey-backed rotation key to your PLC document.</p>

            {identity && !identity.did.startsWith('did:plc:') && (
              <div className="status-strip error">
                This account uses {identity.did}, not did:plc. PLC rotation-key
                updates are only available for did:plc identities.
              </div>
            )}

            {plcSupportError && <div className="status-strip error">{plcSupportError}</div>}

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
                disabled={
                  !!loading ||
                  !identity ||
                  !identity.did.startsWith('did:plc:') ||
                  !!plcSupportError
                }
                type="button"
              >
                {loading === 'request-token' ? 'Requesting...' : 'Request Token'}
              </button>
              <button
                className="button"
                onClick={() => void handleAddRotationKey()}
                disabled={
                  !!loading ||
                  !identity ||
                  !identity.did.startsWith('did:plc:') ||
                  !rotationKeypair ||
                  !!plcSupportError
                }
                type="button"
              >
                {loading === 'add-rotation' ? 'Submitting...' : 'Add Rotation Key'}
              </button>
            </div>

            {recommended && (
              <details className="details-block">
                <summary>Current PLC Shape</summary>
                <div className="result-grid">
                  <div className="result-row">
                    <span className="result-label">Rotation Keys</span>
                    <pre className="mono-block">{formatJson(recommended.rotationKeys)}</pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Verification Methods</span>
                    <pre className="mono-block">{formatJson(recommended.verificationMethods)}</pre>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Services</span>
                    <pre className="mono-block">{formatJson(recommended.services)}</pre>
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
                type="button"
              >
                {loading === 'derive-any-key' ? 'Prompting...' : 'Use Any Available Passkey'}
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
                  type="button"
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
                    <span className="result-value">{rotationKeypair.credentialId}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">did:key</span>
                    <span className="result-value">{rotationKeypair.didKey}</span>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Secret Key (hex)</span>
                    <div className="mono-block">{bytesToHex(rotationKeypair.privateKey)}</div>
                  </div>
                  <div className="result-row">
                    <span className="result-label">Public Key (hex)</span>
                    <div className="mono-block">{bytesToHex(rotationKeypair.publicKey)}</div>
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
