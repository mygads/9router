import { NextResponse } from "next/server";
import { getPublicOAuthSession } from "@/lib/oauth/publicSessions";

export async function GET(request) {
  const { searchParams } = new URL(request.url);
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
