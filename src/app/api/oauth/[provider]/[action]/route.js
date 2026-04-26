import { NextResponse } from "next/server";
import {
  getProvider,
  generateAuthData,
  exchangeTokens,
  requestDeviceCode,
  pollForToken
} from "@/lib/oauth/providers";
import { createProviderConnection } from "@/models";
import { startCodexProxy, stopCodexProxy } from "@/lib/oauth/utils/server";
import { createPublicOAuthSession, getPublicOAuthSession, completePublicOAuthSession } from "@/lib/oauth/publicSessions";

/**
 * Dynamic OAuth API Route
 * Handles: authorize, exchange, device-code, poll
 */

// GET /api/oauth/[provider]/authorize - Generate auth URL
// GET /api/oauth/[provider]/device-code - Request device code (for device_code flow)
export async function GET(request, { params }) {
  try {
    const { provider, action } = await params;
    const { searchParams } = new URL(request.url);

    if (action === "authorize") {
      const redirectUri = searchParams.get("redirect_uri") || "http://localhost:8080/callback";
      const publicCallback = searchParams.get("public_callback") === "true";
      // Collect provider-specific meta params (e.g. gitlab passes baseUrl, clientId, clientSecret)
      const reservedParams = new Set(["redirect_uri", "public_callback"]);
      const meta = {};
      searchParams.forEach((value, key) => { if (!reservedParams.has(key)) meta[key] = value; });

      if (publicCallback) {
        const session = createPublicOAuthSession({
          request,
          provider,
          meta: Object.keys(meta).length ? meta : undefined,
        });
        return NextResponse.json(session);
      }

      const authData = generateAuthData(provider, redirectUri, Object.keys(meta).length ? meta : undefined);
      return NextResponse.json(authData);
    }

    if (action === "session") {
      const state = searchParams.get("state");
      const session = getPublicOAuthSession(state);
      if (!session) {
        return NextResponse.json({ error: "OAuth session not found" }, { status: 404 });
      }

      return NextResponse.json({
        provider: session.provider,
        redirectUri: session.redirectUri,
        expiresAt: new Date(session.expiresAt).toISOString(),
      });
    }

    if (action === "callback-config") {
      const publicBase = (process.env.NEXT_PUBLIC_BASE_URL || process.env.BASE_URL || new URL(request.url).origin).replace(/\/$/, "");
      return NextResponse.json({ callbackUrl: `${publicBase}/callback` });
    }

    if (action === "start-proxy" && searchParams.get("public_callback") === "true") {
      return NextResponse.json({ success: false, reason: "public_callback_mode" });
    }

    if (action === "stop-proxy" && searchParams.get("public_callback") === "true") {
      return NextResponse.json({ success: true });
    }

    if (action === "complete") {
      return NextResponse.json({ error: "Use POST for completion" }, { status: 405 });
    }

    if (action === "start-proxy") {
      if (provider !== "codex") {
        return NextResponse.json({ error: "Proxy only supported for codex" }, { status: 400 });
      }
      const appPort = searchParams.get("app_port");
      if (!appPort) {
        return NextResponse.json({ error: "Missing app_port" }, { status: 400 });
      }
      const result = await startCodexProxy(Number(appPort));
      return NextResponse.json(result);
    }

    if (action === "stop-proxy") {
      if (provider !== "codex") {
        return NextResponse.json({ error: "Proxy only supported for codex" }, { status: 400 });
      }
      stopCodexProxy();
      return NextResponse.json({ success: true });
    }

    if (action === "device-code") {
      const providerData = getProvider(provider);
      if (providerData.flowType !== "device_code") {
        return NextResponse.json({ error: "Provider does not support device code flow" }, { status: 400 });
      }

      const authData = generateAuthData(provider, null);
      const startUrl = searchParams.get("start_url");
      const region = searchParams.get("region");
      const authMethod = searchParams.get("auth_method");
      const deviceOptions = provider === "kiro"
        ? {
            ...(startUrl ? { startUrl } : {}),
            ...(region ? { region } : {}),
            ...(authMethod ? { authMethod } : {}),
          }
        : undefined;
      
      // Providers that don't use PKCE for device code
      const noPkceDeviceProviders = ["github", "kiro", "kimi-coding", "kilocode", "codebuddy"];
      let deviceData;
      if (noPkceDeviceProviders.includes(provider)) {
        deviceData = await requestDeviceCode(provider, undefined, deviceOptions);
      } else {
        // Qwen and other PKCE providers
        deviceData = await requestDeviceCode(provider, authData.codeChallenge, deviceOptions);
      }

      return NextResponse.json({
        ...deviceData,
        codeVerifier: authData.codeVerifier,
      });
    }

    return NextResponse.json({ error: "Unknown action" }, { status: 400 });
  } catch (error) {
    console.log("OAuth GET error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

// POST /api/oauth/[provider]/exchange - Exchange code for tokens and save
// POST /api/oauth/[provider]/poll - Poll for token (device_code flow)
export async function POST(request, { params }) {
  try {
    const { provider, action } = await params;
    let body;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "Invalid or empty request body" }, { status: 400 });
    }

    if (action === "exchange") {
      const { code, redirectUri, codeVerifier, state, meta } = body;

      // Cline uses authorization_code without PKCE
      const noPkceExchangeProviders = ["cline"];
      if (!code || !redirectUri || (!codeVerifier && !noPkceExchangeProviders.includes(provider))) {
        return NextResponse.json({ error: "Missing required fields" }, { status: 400 });
      }

      // Exchange code for tokens (meta carries provider-specific params, e.g. gitlab clientId/baseUrl)
      const tokenData = await exchangeTokens(provider, code, redirectUri, codeVerifier, state, meta);

      // Save to database
      const connection = await createProviderConnection({
        provider,
        authType: "oauth",
        ...tokenData,
        expiresAt: tokenData.expiresIn
          ? new Date(Date.now() + tokenData.expiresIn * 1000).toISOString()
          : null,
        testStatus: "active",
      });

      return NextResponse.json({
        success: true,
        connection: {
          id: connection.id,
          provider: connection.provider,
          email: connection.email,
          displayName: connection.displayName,
        }
      });
    }

    if (action === "complete") {
      const { state, code, error, errorDescription } = body;
      const connection = await completePublicOAuthSession({ state, code, error, errorDescription });
      return NextResponse.json({ success: true, connection });
    }

    if (action === "callback-result") {
      const { state } = body;
      const session = getPublicOAuthSession(state);
      if (!session) {
        return NextResponse.json({ error: "OAuth session not found" }, { status: 404 });
      }

      return NextResponse.json({
        completed: Boolean(session.completed),
        connection: session.connection,
        error: session.error,
      });
    }

    if (action === "callback-config") {
      return NextResponse.json({ error: "Use GET for callback config" }, { status: 405 });
    }

    if (action === "session") {
      return NextResponse.json({ error: "Use GET for session lookup" }, { status: 405 });
    }

    if (action === "authorize") {
      return NextResponse.json({ error: "Use GET for authorization" }, { status: 405 });
    }

    if (action === "device-code") {
      return NextResponse.json({ error: "Use GET for device code" }, { status: 405 });
    }

    if (action === "start-proxy" || action === "stop-proxy") {
      return NextResponse.json({ error: "Use GET for proxy control" }, { status: 405 });
    }

    if (action === "poll") {
      const { deviceCode, codeVerifier, extraData } = body;

      if (!deviceCode) {
        return NextResponse.json({ error: "Missing device code" }, { status: 400 });
      }

      // Providers that don't use PKCE for device code
      const noPkceProviders = ["github", "kimi-coding", "kilocode", "codebuddy"];
      let result;
      if (noPkceProviders.includes(provider)) {
        result = await pollForToken(provider, deviceCode);
      } else if (provider === "kiro") {
        // Kiro needs extraData (clientId, clientSecret) from device code response
        result = await pollForToken(provider, deviceCode, null, extraData);
      } else {
        // Qwen and other PKCE providers
        if (!codeVerifier) {
          return NextResponse.json({ error: "Missing code verifier" }, { status: 400 });
        }
        result = await pollForToken(provider, deviceCode, codeVerifier);
      }

      if (result.success) {
        // Save to database
        const connection = await createProviderConnection({
          provider,
          authType: "oauth",
          ...result.tokens,
          expiresAt: result.tokens.expiresIn 
            ? new Date(Date.now() + result.tokens.expiresIn * 1000).toISOString() 
            : null,
          testStatus: "active",
        });

        return NextResponse.json({ 
          success: true, 
          connection: {
            id: connection.id,
            provider: connection.provider,
          }
        });
      }

      // Still pending or error - don't create connection for pending states
      const isPending = result.pending || result.error === "authorization_pending" || result.error === "slow_down";
      
      return NextResponse.json({
        success: false,
        error: result.error,
        errorDescription: result.errorDescription,
        pending: isPending,
      });
    }

    return NextResponse.json({ error: "Unknown action" }, { status: 400 });
  } catch (error) {
    console.log("OAuth POST error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
