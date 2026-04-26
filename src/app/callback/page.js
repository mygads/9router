"use client";

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

/**
 * OAuth Callback Page Content
 */
function CallbackContent() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState("processing");
  const [message, setMessage] = useState("Please wait while we complete the authorization.");

  useEffect(() => {
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const error = searchParams.get("error");
    const errorDescription = searchParams.get("error_description");
    const callbackData = {
      code,
      state,
      error,
      errorDescription,
      fullUrl: window.location.href,
    };

    const relayCallback = async () => {
      let relayed = false;

      if (window.opener) {
        try {
          window.opener.postMessage({ type: "oauth_callback", data: callbackData }, "*");
          relayed = true;
        } catch (e) {
          console.log("postMessage failed:", e);
        }
      }

      try {
        const channel = new BroadcastChannel("oauth_callback");
        channel.postMessage(callbackData);
        channel.close();
        relayed = true;
      } catch (e) {
        console.log("BroadcastChannel failed:", e);
      }

      try {
        localStorage.setItem("oauth_callback", JSON.stringify({ ...callbackData, timestamp: Date.now() }));
        relayed = true;
      } catch (e) {
        console.log("localStorage failed:", e);
      }

      return relayed;
    };

    const completePublicFlow = async () => {
      if (!(code || error) || !state) {
        setTimeout(() => setStatus("manual"), 0);
        return;
      }

      try {
        const sessionRes = await fetch(`/api/oauth/callback/session?state=${encodeURIComponent(state)}`, {
          cache: "no-store",
        });

        if (!sessionRes.ok) {
          await relayCallback();
          setStatus("success");
          setTimeout(() => {
            window.close();
            setTimeout(() => setStatus("done"), 500);
          }, 1500);
          return;
        }

        const session = await sessionRes.json();
        const completeRes = await fetch(`/api/oauth/${session.provider}/complete`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ state, code, error, errorDescription }),
        });

        const completeData = await completeRes.json();
        if (!completeRes.ok) {
          throw new Error(completeData.error || "Failed to complete OAuth callback");
        }

        await relayCallback();
        setMessage("Authorization completed successfully. This window will close automatically...");
        setStatus("success");
        setTimeout(() => {
          window.close();
          setTimeout(() => setStatus("done"), 500);
        }, 1500);
      } catch (e) {
        console.log("Public callback completion failed:", e);
        const relayed = await relayCallback();
        if (relayed) {
          setMessage("Authorization data was returned to the app. If the popup stays open, you can close it.");
          setStatus("success");
          setTimeout(() => {
            window.close();
            setTimeout(() => setStatus("done"), 500);
          }, 1500);
        } else {
          setStatus("manual");
        }
      }
    };

    completePublicFlow();
  }, [searchParams]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg">
      <div className="text-center p-8 max-w-md">
        {status === "processing" && (
          <>
            <div className="size-16 mx-auto mb-4 rounded-full bg-primary/10 flex items-center justify-center">
              <span className="material-symbols-outlined text-3xl text-primary animate-spin">progress_activity</span>
            </div>
            <h1 className="text-xl font-semibold mb-2">Processing...</h1>
            <p className="text-text-muted">{message}</p>
          </>
        )}

        {(status === "success" || status === "done") && (
          <>
            <div className="size-16 mx-auto mb-4 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
              <span className="material-symbols-outlined text-3xl text-green-600">check_circle</span>
            </div>
            <h1 className="text-xl font-semibold mb-2">Authorization Successful!</h1>
            <p className="text-text-muted">
              {status === "success" ? "This window will close automatically..." : "You can close this tab now."}
            </p>
          </>
        )}

        {status === "manual" && (
          <>
            <div className="size-16 mx-auto mb-4 rounded-full bg-yellow-100 dark:bg-yellow-900/30 flex items-center justify-center">
              <span className="material-symbols-outlined text-3xl text-yellow-600">info</span>
            </div>
            <h1 className="text-xl font-semibold mb-2">Copy This URL</h1>
            <p className="text-text-muted mb-4">
              Please copy the URL from the address bar and paste it in the application.
            </p>
            <div className="bg-surface border border-border rounded-lg p-3 text-left">
              <code className="text-xs break-all">{typeof window !== "undefined" ? window.location.href : ""}</code>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * OAuth Callback Page
 * Receives callback from OAuth providers and sends data back via multiple methods
 */
export default function CallbackPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-bg">
        <div className="text-center p-8">
          <div className="size-16 mx-auto mb-4 rounded-full bg-primary/10 flex items-center justify-center">
            <span className="material-symbols-outlined text-3xl text-primary animate-spin">progress_activity</span>
          </div>
          <p className="text-text-muted">Loading...</p>
        </div>
      </div>
    }>
      <CallbackContent />
    </Suspense>
  );
}
