import { Agent, AtpAgent, type AtpSessionData } from "@atproto/api";
import {
  BrowserOAuthClient,
  type OAuthSession,
} from "@atproto/oauth-client-browser";
import * as dagCbor from "@ipld/dag-cbor";

const SLINGSHOT_URL = "https://slingshot.microcosm.blue";
const PLC_DIRECTORY_URL = "https://plc.directory";
const OAUTH_SCOPE = "atproto identity:*";
const OAUTH_METADATA_PATH = "/oauth/client-metadata.json";
const DEFAULT_HANDLE_RESOLVER = "https://bsky.social";

export type AtprotoSessionData = AtpSessionData;

export type DidDocument = {
  id: string;
  service?: Array<{
    id: string;
    type: string;
    serviceEndpoint: string | Record<string, unknown>;
  }>;
};

export type ResolvedIdentity = {
  did: string;
  handle: string;
  pdsUrl: string;
  didDoc: DidDocument;
  signingKey?: string;
};

export type RecommendedDidCredentials = {
  rotationKeys: string[];
  alsoKnownAs: string[];
  verificationMethods: Record<string, unknown>;
  services: Record<string, unknown>;
};

export type PlcData = {
  did: string;
  rotationKeys: string[];
  alsoKnownAs: string[];
  verificationMethods: Record<string, unknown>;
  services: Record<string, unknown>;
};

export type PlcAuditEntry = {
  did: string;
  cid: string;
  nullified?: boolean;
  createdAt?: string;
  operation: Record<string, unknown>;
};

export type PlcUnsignedOperation = {
  type: "plc_operation";
  rotationKeys: string[];
  alsoKnownAs: string[];
  verificationMethods: Record<string, unknown>;
  services: Record<string, unknown>;
  prev: string | null;
};

export type PlcSignedOperation = PlcUnsignedOperation & {
  sig: string;
};

export type LegacySavedSession = {
  kind?: "legacy";
  pdsUrl: string;
  session: AtprotoSessionData;
};

export type OAuthSavedSession = {
  kind: "oauth";
  did: string;
};

export type SavedSession = LegacySavedSession | OAuthSavedSession;

export type AtprotoClient = {
  agent: Agent;
  pdsUrl: string;
  auth:
    | {
        kind: "oauth";
        did: string;
        session: OAuthSession;
        grantedScopes: string[];
      }
    | {
        kind: "legacy";
        session: AtprotoSessionData;
      };
};

let oauthClientPromise: Promise<BrowserOAuthClient> | null = null;

function toErrorMessage(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

export function getErrorMessage(error: unknown) {
  return toErrorMessage(error);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isLegacySavedSession(value: unknown): value is LegacySavedSession {
  return (
    isRecord(value) &&
    typeof value.pdsUrl === "string" &&
    isRecord(value.session)
  );
}

export function normalizeSavedSession(value: unknown): SavedSession | null {
  if (!isRecord(value)) {
    return null;
  }

  if (value.kind === "oauth" && typeof value.did === "string") {
    return {
      kind: "oauth",
      did: value.did,
    };
  }

  if (isLegacySavedSession(value)) {
    return {
      kind: "legacy",
      pdsUrl: value.pdsUrl,
      session: value.session as AtprotoSessionData,
    };
  }

  return null;
}

async function readJsonBody<T>(response: Response): Promise<T | undefined> {
  const text = await response.text();

  if (!text.trim()) {
    return undefined;
  }

  return JSON.parse(text) as T;
}

async function parseError(response: Response) {
  try {
    const payload = await readJsonBody<{ message?: string; error?: string }>(
      response,
    );
    return (
      payload?.message ??
      payload?.error ??
      `Request failed with status ${response.status}.`
    );
  } catch {
    return `Request failed with status ${response.status}.`;
  }
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === "string")
  );
}

function parseGrantedScopes(scope: string) {
  return scope
    .split(/\s+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function isLoopbackHost(hostname: string) {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1"
  );
}

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, "");
}

function getProductionBaseUrl() {
  const configured =
    import.meta.env.VITE_PUBLIC_URL?.trim() ?? "https://plc-passkey.wisp.place";
  if (configured) {
    return trimTrailingSlash(configured);
  }

  return trimTrailingSlash(window.location.origin);
}

function getRedirectUri(baseUrl: string) {
  return `${baseUrl}/`;
}

function createOAuthClientMetadata() {
  const baseUrl = getProductionBaseUrl();
  return {
    client_id: `${baseUrl}${OAUTH_METADATA_PATH}`,
    client_name: "PLC Passkey",
    client_uri: `${baseUrl}/`,
    logo_uri: `${baseUrl}/favicon.svg`,
    redirect_uris: [getRedirectUri(baseUrl)] as [string],
    scope: OAUTH_SCOPE,
    grant_types: ["authorization_code", "refresh_token"] as [
      "authorization_code",
      "refresh_token",
    ],
    response_types: ["code"] as ["code"],
    token_endpoint_auth_method: "none" as const,
    application_type: "web" as const,
    dpop_bound_access_tokens: true,
  };
}

async function getOAuthClient() {
  if (!oauthClientPromise) {
    oauthClientPromise = Promise.resolve().then(() => {
      if (typeof window === "undefined") {
        throw new Error("OAuth login is only available in the browser.");
      }

      if (isLoopbackHost(window.location.hostname)) {
        return new BrowserOAuthClient({
          clientMetadata: undefined,
          handleResolver: DEFAULT_HANDLE_RESOLVER,
        });
      }

      return new BrowserOAuthClient({
        clientMetadata: createOAuthClientMetadata(),
        handleResolver: DEFAULT_HANDLE_RESOLVER,
      });
    });
  }

  return oauthClientPromise;
}

function buildLegacyClient(agent: AtpAgent): AtprotoClient {
  const session = agent.session;

  if (!session) {
    throw new Error("PDS returned an unexpected session payload.");
  }

  return {
    agent,
    pdsUrl: agent.dispatchUrl.toString(),
    auth: {
      kind: "legacy",
      session,
    },
  };
}

async function buildOAuthClient(session: OAuthSession): Promise<AtprotoClient> {
  const agent = new Agent(session);
  const tokenInfo = await session.getTokenInfo();
  const identity = await resolveIdentity(session.did);

  return {
    agent,
    pdsUrl: identity.pdsUrl,
    auth: {
      kind: "oauth",
      did: session.did,
      session,
      grantedScopes: parseGrantedScopes(tokenInfo.scope),
    },
  };
}

export function getRequiredOAuthScope() {
  return OAUTH_SCOPE;
}

export function supportsPlcOperations(client: AtprotoClient) {
  if (client.auth.kind !== "oauth") {
    return true;
  }

  return client.auth.grantedScopes.includes("identity:*");
}

export function getPlcSupportError(client: AtprotoClient) {
  if (supportsPlcOperations(client)) {
    return null;
  }

  if (client.auth.kind === "oauth") {
    const granted = client.auth.grantedScopes.join(" ") || "(none)";
    return `This OAuth session is missing the required scope identity:*. Granted scopes: ${granted}`;
  }

  return null;
}

export function getSavedSessionForClient(client: AtprotoClient): SavedSession {
  if (client.auth.kind === "oauth") {
    return {
      kind: "oauth",
      did: client.auth.did,
    };
  }

  return {
    kind: "legacy",
    pdsUrl: client.pdsUrl,
    session: client.auth.session,
  };
}

export async function logoutClient(client: AtprotoClient) {
  if (client.auth.kind === "oauth") {
    const oauthClient = await getOAuthClient();
    await oauthClient.revoke(client.auth.did);
    return;
  }

  await (client.agent as AtpAgent).logout();
}

export async function resolveIdentity(
  identifier: string,
): Promise<ResolvedIdentity> {
  const url = new URL(
    "/xrpc/blue.microcosm.identity.resolveMiniDoc",
    SLINGSHOT_URL,
  );
  url.searchParams.set("identifier", identifier);

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  const payload = await readJsonBody<{
    did: string;
    handle: string;
    pds: string;
    signing_key?: string;
  }>(response);

  if (!payload) {
    throw new Error("Slingshot returned an empty identity payload.");
  }

  if (typeof payload.did !== "string" || typeof payload.handle !== "string") {
    throw new Error("Slingshot returned an invalid identity payload.");
  }

  if (typeof payload.pds !== "string" || !payload.pds) {
    throw new Error(
      "Slingshot did not return a PDS endpoint for this identity.",
    );
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
              id: "#atproto_pds",
              type: "AtprotoPersonalDataServer",
              serviceEndpoint: payload.pds,
            },
          ]
        : undefined,
    },
  };
}

export async function beginOAuthLogin(identifier: string) {
  const oauthClient = await getOAuthClient();
  await oauthClient.signIn(identifier.trim());
}

export async function restorePreviousSession(
  saved: SavedSession | null,
): Promise<{
  client: AtprotoClient;
  identity: ResolvedIdentity;
  saved: SavedSession;
  restoredFromCallback: boolean;
} | null> {
  const oauthClient = await getOAuthClient();

  const callbackParams = oauthClient.readCallbackParams();
  if (callbackParams) {
    const callbackResult = await oauthClient.initCallback(callbackParams);
    const client = await buildOAuthClient(callbackResult.session);
    const identity = await resolveIdentity(callbackResult.session.did);
    return {
      client,
      identity,
      saved: getSavedSessionForClient(client),
      restoredFromCallback: true,
    };
  }

  if (saved?.kind === "oauth") {
    const session = await oauthClient.restore(saved.did);
    const client = await buildOAuthClient(session);
    const identity = await resolveIdentity(session.did);
    return {
      client,
      identity,
      saved: getSavedSessionForClient(client),
      restoredFromCallback: false,
    };
  }

  if (!saved) {
    const restored = await oauthClient.initRestore();
    if (!restored) {
      return null;
    }

    const client = await buildOAuthClient(restored.session);
    const identity = await resolveIdentity(restored.session.did);
    return {
      client,
      identity,
      saved: getSavedSessionForClient(client),
      restoredFromCallback: false,
    };
  }

  const agent = new AtpAgent({ service: saved.pdsUrl });
  await agent.resumeSession(saved.session);
  const client = buildLegacyClient(agent);
  const identity = await resolveIdentity(client.auth.session.did);
  return {
    client,
    identity,
    saved: getSavedSessionForClient(client),
    restoredFromCallback: false,
  };
}

export async function loginWithAtproto(params: {
  identifier: string;
  password: string;
  pdsUrl?: string;
}) {
  const resolved = params.pdsUrl
    ? null
    : await resolveIdentity(params.identifier.trim());
  const pdsUrl = params.pdsUrl?.trim() || resolved?.pdsUrl;

  if (!pdsUrl) {
    throw new Error("Unable to determine the PDS URL for this account.");
  }

  const agent = new AtpAgent({ service: pdsUrl });
  const response = await agent.login({
    identifier: params.identifier.trim(),
    password: params.password,
  });

  const client = buildLegacyClient(agent);
  const identity = resolved ?? (await resolveIdentity(response.data.did));

  return {
    client,
    identity,
    session: client.auth.session,
  };
}

export async function getRecommendedDidCredentials(
  client: AtprotoClient,
): Promise<RecommendedDidCredentials> {
  const response =
    await client.agent.com.atproto.identity.getRecommendedDidCredentials();
  const data = response.data;

  return {
    rotationKeys: data.rotationKeys ?? [],
    alsoKnownAs: data.alsoKnownAs ?? [],
    verificationMethods: data.verificationMethods ?? {},
    services: data.services ?? {},
  };
}

export async function getCurrentPlcData(did: string): Promise<PlcData> {
  const response = await fetch(new URL(`/${did}/data`, PLC_DIRECTORY_URL));

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  const payload = await readJsonBody<{
    did: string;
    rotationKeys?: string[];
    alsoKnownAs?: string[];
    verificationMethods?: Record<string, unknown>;
    services?: Record<string, unknown>;
  }>(response);

  if (!payload || typeof payload.did !== "string") {
    throw new Error("PLC directory returned an invalid current PLC document.");
  }

  return {
    did: payload.did,
    rotationKeys: payload.rotationKeys ?? [],
    alsoKnownAs: payload.alsoKnownAs ?? [],
    verificationMethods: payload.verificationMethods ?? {},
    services: payload.services ?? {},
  };
}

export async function getPlcAuditLog(did: string): Promise<PlcAuditEntry[]> {
  const response = await fetch(new URL(`/${did}/log/audit`, PLC_DIRECTORY_URL));

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  const payload = await readJsonBody<unknown>(response);

  if (!Array.isArray(payload)) {
    throw new Error("PLC directory returned an invalid audit log payload.");
  }

  return payload
    .filter((entry): entry is PlcAuditEntry => {
      if (!isRecord(entry)) {
        return false;
      }

      return (
        typeof entry.did === "string" &&
        typeof entry.cid === "string" &&
        isRecord(entry.operation)
      );
    })
    .map((entry) => ({
      did: entry.did,
      cid: entry.cid,
      nullified: entry.nullified === true,
      createdAt:
        typeof entry.createdAt === "string" ? entry.createdAt : undefined,
      operation: entry.operation,
    }));
}

export function getLatestValidAuditEntry(
  entries: PlcAuditEntry[],
): PlcAuditEntry {
  const latest = [...entries].reverse().find((entry) => !entry.nullified);

  if (!latest) {
    throw new Error("No valid PLC audit entry was found for this DID.");
  }

  return latest;
}

export function createUnsignedPlcOperation(params: {
  prev: string | null;
  rotationKeys: string[];
  alsoKnownAs: string[];
  verificationMethods: Record<string, unknown>;
  services: Record<string, unknown>;
}): PlcUnsignedOperation {
  return {
    type: "plc_operation",
    rotationKeys: params.rotationKeys,
    alsoKnownAs: params.alsoKnownAs,
    verificationMethods: params.verificationMethods,
    services: params.services,
    prev: params.prev,
  };
}

export function encodeUnsignedPlcOperation(operation: PlcUnsignedOperation) {
  return dagCbor.encode(operation);
}

export async function submitDirectPlcOperation(
  did: string,
  operation: PlcSignedOperation,
) {
  const response = await fetch(new URL(`/${did}`, PLC_DIRECTORY_URL), {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify(operation),
  });

  if (!response.ok) {
    throw new Error(await parseError(response));
  }

  return response;
}

export function parseRawPlcOperation(value: string): PlcUnsignedOperation {
  let parsed: unknown;

  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    throw new Error("Raw PLC JSON is invalid.");
  }

  if (!isRecord(parsed)) {
    throw new Error("Raw PLC JSON must be an object.");
  }

  if (parsed.type !== "plc_operation") {
    throw new Error('Raw PLC JSON must set "type" to "plc_operation".');
  }

  if (!isStringArray(parsed.rotationKeys)) {
    throw new Error('Raw PLC JSON must include a string array "rotationKeys".');
  }

  if (!isStringArray(parsed.alsoKnownAs)) {
    throw new Error('Raw PLC JSON must include a string array "alsoKnownAs".');
  }

  if (!isRecord(parsed.verificationMethods)) {
    throw new Error(
      'Raw PLC JSON must include an object "verificationMethods".',
    );
  }

  if (!isRecord(parsed.services)) {
    throw new Error('Raw PLC JSON must include an object "services".');
  }

  if (!(typeof parsed.prev === "string" || parsed.prev === null)) {
    throw new Error('Raw PLC JSON must include "prev" as a string or null.');
  }

  return {
    type: "plc_operation",
    rotationKeys: parsed.rotationKeys,
    alsoKnownAs: parsed.alsoKnownAs,
    verificationMethods: parsed.verificationMethods,
    services: parsed.services,
    prev: parsed.prev,
  };
}

export async function requestPlcOperationSignature(client: AtprotoClient) {
  const plcError = getPlcSupportError(client);
  if (plcError) {
    throw new Error(plcError);
  }

  await client.agent.com.atproto.identity.requestPlcOperationSignature();
}

export async function addRotationKeyFromPasskey(params: {
  client: AtprotoClient;
  passkeyDidKey: string;
  token?: string;
}) {
  const plcError = getPlcSupportError(params.client);
  if (plcError) {
    throw new Error(plcError);
  }

  const currentPlc = await getCurrentPlcData(params.client.agent.assertDid);
  const rotationKeys = Array.from(
    new Set([...currentPlc.rotationKeys, params.passkeyDidKey]),
  );

  const signed =
    await params.client.agent.com.atproto.identity.signPlcOperation({
      rotationKeys,
      alsoKnownAs: currentPlc.alsoKnownAs,
      verificationMethods: currentPlc.verificationMethods,
      services: currentPlc.services,
      token: params.token?.trim() || undefined,
    });

  await params.client.agent.com.atproto.identity.submitPlcOperation({
    operation: signed.data.operation,
  });

  return {
    operation: signed.data.operation,
    rotationKeys,
  };
}
