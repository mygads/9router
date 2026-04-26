import { generateAuthData, exchangeTokens } from "./providers";
import { createProviderConnection } from "@/models";

const SESSION_TTL_MS = 10 * 60 * 1000;

if (!global._oauthPublicSessions) {
  global._oauthPublicSessions = new Map();
}

const sessions = global._oauthPublicSessions;

function cleanupExpiredSessions() {
  const now = Date.now();
  for (const [state, session] of sessions.entries()) {
    if (session.expiresAt <= now || session.completed) {
      sessions.delete(state);
    }
  }
}

function getPublicBaseUrl(request) {
  const configured = process.env.NEXT_PUBLIC_BASE_URL || process.env.BASE_URL;
  if (configured) return configured.replace(/\/$/, "");

  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

function buildCallbackUrl(request, provider) {
  const publicBase = getPublicBaseUrl(request);
  if (provider === "codex") {
    return `${publicBase}/auth/callback`;
  }
  return `${publicBase}/callback`;
}

export function createPublicOAuthSession({ request, provider, meta }) {
  cleanupExpiredSessions();

  const redirectUri = buildCallbackUrl(request, provider);
  const authData = generateAuthData(provider, redirectUri, meta);
  const session = {
    provider,
    meta: meta || null,
    redirectUri,
    codeVerifier: authData.codeVerifier,
    state: authData.state,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    completed: false,
    connection: null,
    error: null,
  };

  sessions.set(authData.state, session);

  return {
    authUrl: authData.authUrl,
    state: authData.state,
    redirectUri,
    flowType: authData.flowType,
    callbackPath: authData.callbackPath,
    expiresAt: new Date(session.expiresAt).toISOString(),
    publicCallback: true,
  };
}

export function getPublicOAuthSession(state) {
  cleanupExpiredSessions();
  if (!state) return null;
  return sessions.get(state) || null;
}

export async function completePublicOAuthSession({ state, code, error, errorDescription }) {
  cleanupExpiredSessions();

  const session = getPublicOAuthSession(state);
  if (!session) {
    throw new Error("OAuth session expired or not found");
  }

  if (session.completed) {
    throw new Error("OAuth session has already been completed");
  }

  if (error) {
    session.completed = true;
    session.error = errorDescription || error;
    sessions.delete(state);
    throw new Error(session.error);
  }

  if (!code) {
    throw new Error("Missing authorization code");
  }

  const tokenData = await exchangeTokens(
    session.provider,
    code,
    session.redirectUri,
    session.codeVerifier,
    state,
    session.meta || undefined
  );

  const connection = await createProviderConnection({
    provider: session.provider,
    authType: "oauth",
    ...tokenData,
    expiresAt: tokenData.expiresIn
      ? new Date(Date.now() + tokenData.expiresIn * 1000).toISOString()
      : null,
    testStatus: "active",
  });

  session.completed = true;
  session.connection = {
    id: connection.id,
    provider: connection.provider,
    email: connection.email,
    displayName: connection.displayName,
  };
  sessions.delete(state);

  return session.connection;
}
