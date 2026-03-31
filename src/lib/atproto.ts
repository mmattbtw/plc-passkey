const SLINGSHOT_URL = 'https://slingshot.microcosm.blue'

export type AtprotoSessionData = {
  refreshJwt: string
  accessJwt: string
  handle: string
  did: string
  email?: string
  emailConfirmed?: boolean
  emailAuthFactor?: boolean
  active: boolean
  status?: string
}

export type AtprotoClient = {
  pdsUrl: string
  session: AtprotoSessionData
}

export type SavedSession = {
  pdsUrl: string
  session: AtprotoSessionData
}

export type DidDocument = {
  id: string
  service?: Array<{
    id: string
    type: string
    serviceEndpoint: string | Record<string, unknown>
  }>
}

export type ResolvedIdentity = {
  did: string
  handle: string
  pdsUrl: string
  didDoc: DidDocument
  signingKey?: string
}

export type RecommendedDidCredentials = {
  rotationKeys: string[]
  alsoKnownAs: string[]
  verificationMethods: Record<string, unknown>
  services: Record<string, unknown>
}

function toErrorMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message
  }

  return String(error)
}

export function getErrorMessage(error: unknown) {
  return toErrorMessage(error)
}

async function readJsonBody<T>(response: Response): Promise<T | undefined> {
  const text = await response.text()

  if (!text.trim()) {
    return undefined
  }

  return JSON.parse(text) as T
}

async function parseError(response: Response) {
  try {
    const payload = await readJsonBody<{ message?: string; error?: string }>(response)
    return (
      payload?.message ??
      payload?.error ??
      `Request failed with status ${response.status}.`
    )
  } catch {
    return `Request failed with status ${response.status}.`
  }
}

async function xrpc<T>(serviceUrl: string, nsid: string, init?: RequestInit): Promise<T> {
  const response = await fetch(new URL(`/xrpc/${nsid}`, serviceUrl), init)

  if (!response.ok) {
    throw new Error(await parseError(response))
  }

  if (response.status === 204) {
    return undefined as T
  }

  const payload = await readJsonBody<T>(response)

  if (payload === undefined) {
    return undefined as T
  }

  return payload
}

function buildSession(payload: Partial<AtprotoSessionData>): AtprotoSessionData {
  if (
    typeof payload.accessJwt !== 'string' ||
    typeof payload.refreshJwt !== 'string' ||
    typeof payload.handle !== 'string' ||
    typeof payload.did !== 'string'
  ) {
    throw new Error('PDS returned an unexpected session payload.')
  }

  return {
    accessJwt: payload.accessJwt,
    refreshJwt: payload.refreshJwt,
    handle: payload.handle,
    did: payload.did,
    email: payload.email,
    emailConfirmed: payload.emailConfirmed,
    emailAuthFactor: payload.emailAuthFactor,
    active: payload.active ?? true,
    status: payload.status,
  }
}

function authHeaders(token: string) {
  return {
    authorization: `Bearer ${token}`,
  }
}

export async function resolveIdentity(identifier: string): Promise<ResolvedIdentity> {
  const url = new URL('/xrpc/blue.microcosm.identity.resolveMiniDoc', SLINGSHOT_URL)
  url.searchParams.set('identifier', identifier)

  const response = await fetch(url)

  if (!response.ok) {
    throw new Error(await parseError(response))
  }

  const payload = await readJsonBody<{
    did: string
    handle: string
    pds: string
    signing_key?: string
  }>(response)

  if (!payload) {
    throw new Error('Slingshot returned an empty identity payload.')
  }

  if (typeof payload.did !== 'string' || typeof payload.handle !== 'string') {
    throw new Error('Slingshot returned an invalid identity payload.')
  }

  if (typeof payload.pds !== 'string' || !payload.pds) {
    throw new Error('Slingshot did not return a PDS endpoint for this identity.')
  }

  return {
    did: payload.did,
    handle: payload.handle,
    pdsUrl: payload.pds,
    signingKey: payload.signing_key,
    didDoc: {
      id: payload.did,
      service: payload.pds
        ? [
            {
              id: '#atproto_pds',
              type: 'AtprotoPersonalDataServer',
              serviceEndpoint: payload.pds,
            },
          ]
        : undefined,
    },
  }
}

export async function loginWithAtproto(params: {
  identifier: string
  password: string
  pdsUrl?: string
}) {
  const resolved = params.pdsUrl ? null : await resolveIdentity(params.identifier.trim())
  const pdsUrl = params.pdsUrl?.trim() || resolved?.pdsUrl

  if (!pdsUrl) {
    throw new Error('Unable to determine the PDS URL for this account.')
  }

  const payload = await xrpc<AtprotoSessionData>(
    pdsUrl,
    'com.atproto.server.createSession',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        identifier: params.identifier.trim(),
        password: params.password,
      }),
    },
  )

  const session = buildSession(payload)
  const identity = resolved ?? (await resolveIdentity(session.did))

  return {
    client: {
      pdsUrl,
      session,
    } satisfies AtprotoClient,
    identity,
    session,
  }
}

export async function resumeSavedSession(saved: SavedSession) {
  const payload = await xrpc<AtprotoSessionData>(
    saved.pdsUrl,
    'com.atproto.server.refreshSession',
    {
      method: 'POST',
      headers: {
        ...authHeaders(saved.session.refreshJwt),
      },
    },
  )

  const session = buildSession(payload)
  const identity = await resolveIdentity(session.did)

  return {
    client: {
      pdsUrl: saved.pdsUrl,
      session,
    } satisfies AtprotoClient,
    identity,
    session,
  }
}

export async function getRecommendedDidCredentials(client: AtprotoClient): Promise<RecommendedDidCredentials> {
  const data = await xrpc<{
    rotationKeys?: string[]
    alsoKnownAs?: string[]
    verificationMethods?: Record<string, unknown>
    services?: Record<string, unknown>
  }>(client.pdsUrl, 'com.atproto.identity.getRecommendedDidCredentials', {
    headers: {
      ...authHeaders(client.session.accessJwt),
    },
  })

  return {
    rotationKeys: data.rotationKeys ?? [],
    alsoKnownAs: data.alsoKnownAs ?? [],
    verificationMethods: data.verificationMethods ?? {},
    services: data.services ?? {},
  }
}

export async function requestPlcOperationSignature(client: AtprotoClient) {
  await xrpc(
    client.pdsUrl,
    'com.atproto.identity.requestPlcOperationSignature',
    {
      method: 'POST',
      headers: {
        ...authHeaders(client.session.accessJwt),
      },
    },
  )
}

export async function addRotationKeyFromPasskey(params: {
  client: AtprotoClient
  passkeyDidKey: string
  token?: string
}) {
  const recommended = await getRecommendedDidCredentials(params.client)
  const rotationKeys = Array.from(new Set([...recommended.rotationKeys, params.passkeyDidKey]))

  const signed = await xrpc<{ operation: Record<string, unknown> }>(
    params.client.pdsUrl,
    'com.atproto.identity.signPlcOperation',
    {
      method: 'POST',
      headers: {
        ...authHeaders(params.client.session.accessJwt),
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        rotationKeys,
        alsoKnownAs: recommended.alsoKnownAs,
        verificationMethods: recommended.verificationMethods,
        services: recommended.services,
        token: params.token?.trim() || undefined,
      }),
    },
  )

  await xrpc(params.client.pdsUrl, 'com.atproto.identity.submitPlcOperation', {
    method: 'POST',
    headers: {
      ...authHeaders(params.client.session.accessJwt),
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      operation: signed.operation,
    }),
  })

  return {
    operation: signed.operation,
    rotationKeys,
  }
}
