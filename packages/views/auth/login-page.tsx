"use client";

import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@multica/ui/components/ui/card";
import { Input } from "@multica/ui/components/ui/input";
import { Button } from "@multica/ui/components/ui/button";
import { Label } from "@multica/ui/components/ui/label";
import { useAuthStore } from "@multica/core/auth";
import { useConfigStore } from "@multica/core/config";
import { workspaceKeys } from "@multica/core/workspace/queries";
import { api } from "@multica/core/api";
import type { User } from "@multica/core/types";
import { useT } from "../i18n";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CliCallbackConfig {
  /** Validated localhost callback URL */
  url: string;
  /** Opaque state to pass back to CLI */
  state: string;
}

interface LoginPageProps {
  /** Logo element rendered above the title */
  logo?: ReactNode;
  /** Called after successful login. The workspace list is seeded into React
   *  Query before this fires, so the caller can compute a destination URL. */
  onSuccess: () => void;
  /** CLI callback config for authorizing CLI tools. */
  cliCallback?: CliCallbackConfig;
  /** Called after a token is obtained (e.g. to set cookies). */
  onTokenObtained?: () => void;
}

/** Mirrors minPasswordLength in server/internal/handler/auth.go. */
const MIN_PASSWORD_LENGTH = 8;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function redirectToCliCallback(url: string, token: string, state: string) {
  const separator = url.includes("?") ? "&" : "?";
  window.location.href = `${url}${separator}token=${encodeURIComponent(token)}&state=${encodeURIComponent(state)}`;
}

/**
 * Validate that a CLI callback URL points to a safe host over HTTP.
 * Allows localhost and private/LAN IPs (RFC 1918) to support self-hosted setups
 * on local VMs while blocking arbitrary public hosts.
 */
export function validateCliCallback(cliCallback: string): boolean {
  try {
    const cbUrl = new URL(cliCallback);
    if (cbUrl.protocol !== "http:") return false;
    const h = cbUrl.hostname;
    if (h === "localhost" || h === "127.0.0.1") return true;
    // Allow RFC 1918 private IPs: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
    if (/^10\./.test(h)) return true;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
    if (/^192\.168\./.test(h)) return true;
    return false;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function LoginPage({
  logo,
  onSuccess,
  cliCallback,
  onTokenObtained,
}: LoginPageProps) {
  const { t } = useT("auth");
  const qc = useQueryClient();
  const allowSignup = useConfigStore((s) => s.allowSignup);
  const [step, setStep] = useState<"credentials" | "cli_confirm">("credentials");
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [existingUser, setExistingUser] = useState<User | null>(null);
  // Tracks how the existing session was detected so handleCliAuthorize
  // uses the matching token source (cookie → issueCliToken, localStorage → direct).
  const authSourceRef = useRef<"cookie" | "localStorage">("cookie");

  // Check for existing session when CLI callback is present.
  // Prioritises cookie auth (= current browser session) to avoid authorising
  // the CLI with a stale or mismatched localStorage token.
  useEffect(() => {
    if (!cliCallback) return;

    // Ensure no stale bearer token interferes — we want to test the cookie first.
    api.setToken(null);

    api
      .getMe()
      .then((user) => {
        authSourceRef.current = "cookie";
        setExistingUser(user);
        setStep("cli_confirm");
      })
      .catch(() => {
        // Cookie auth failed — fall back to localStorage token
        const token = localStorage.getItem("multica_token");
        if (!token) return;

        api.setToken(token);
        api
          .getMe()
          .then((user) => {
            authSourceRef.current = "localStorage";
            setExistingUser(user);
            setStep("cli_confirm");
          })
          .catch(() => {
            api.setToken(null);
            localStorage.removeItem("multica_token");
          });
      });
  }, [cliCallback]);

  const handleSubmit = useCallback(
    async (e?: React.FormEvent) => {
      e?.preventDefault();
      if (!email) {
        setError(t(($) => $.common.email_required));
        return;
      }
      if (!password) {
        setError(t(($) => $.common.password_required));
        return;
      }
      // Mirror the server's floor so a doomed signup costs no round trip.
      if (mode === "signup" && password.length < MIN_PASSWORD_LENGTH) {
        setError(t(($) => $.common.password_too_short));
        return;
      }

      setLoading(true);
      setError("");
      try {
        if (cliCallback) {
          // CLI path: take the token directly for the redirect URL.
          const { token } =
            mode === "signup"
              ? await api.signupWithPassword(email, password)
              : await api.loginWithPassword(email, password);
          localStorage.setItem("multica_token", token);
          api.setToken(token);
          onTokenObtained?.();
          redirectToCliCallback(cliCallback.url, token, cliCallback.state);
          return;
        }

        // Normal path: seed the workspace list into the Query cache so the
        // caller's onSuccess can compute a destination synchronously.
        if (mode === "signup") {
          await useAuthStore.getState().signupWithPassword(email, password);
        } else {
          await useAuthStore.getState().loginWithPassword(email, password);
        }
        const wsList = await api.listWorkspaces();
        qc.setQueryData(workspaceKeys.list(), wsList);
        onTokenObtained?.();
        onSuccess();
      } catch (err) {
        setError(
          err instanceof Error
            ? err.message
            : t(($) =>
                mode === "signup" ? $.errors.signup_failed : $.errors.credentials_invalid,
              ),
        );
        setLoading(false);
      }
    },
    [cliCallback, email, mode, onSuccess, onTokenObtained, password, qc, t],
  );

  const handleCliAuthorize = async () => {
    if (!cliCallback) return;
    setLoading(true);

    try {
      let token: string;

      if (authSourceRef.current === "localStorage") {
        // Session was detected via localStorage — reuse that token directly.
        const stored = localStorage.getItem("multica_token");
        if (!stored) throw new Error("token missing");
        token = stored;
      } else {
        // Session was detected via cookie — obtain a bearer token from the server.
        const res = await api.issueCliToken();
        token = res.token;
      }

      onTokenObtained?.();
      redirectToCliCallback(cliCallback.url, token, cliCallback.state);
    } catch {
      setError(t(($) => $.errors.cli_auth_failed));
      setExistingUser(null);
      setStep("credentials");
      setLoading(false);
    }
  };

  // -------------------------------------------------------------------------
  // CLI confirm step
  // -------------------------------------------------------------------------

  if (step === "cli_confirm" && existingUser) {
    return (
      <div className="flex min-h-svh items-center justify-center">
        <Card className="w-full max-w-sm">
          <CardHeader className="text-center">
            {logo && <div className="mx-auto mb-4">{logo}</div>}
            <CardTitle className="text-display-sm">
              {t(($) => $.cli.title)}
            </CardTitle>
            <CardDescription>
              {t(($) => $.cli.description, { email: existingUser.email })}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <Button
              onClick={handleCliAuthorize}
              disabled={loading}
              className="w-full"
              size="lg"
            >
              {loading
                ? t(($) => $.cli.authorizing)
                : t(($) => $.cli.authorize)}
            </Button>
            <Button
              variant="ghost"
              className="w-full"
              onClick={() => {
                setExistingUser(null);
                setStep("credentials");
              }}
            >
              {t(($) => $.cli.different_account)}
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Credentials step
  // -------------------------------------------------------------------------

  return (
    <div className="flex min-h-svh items-center justify-center">
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          {logo && <div className="mx-auto mb-4">{logo}</div>}
          <CardTitle className="text-display-sm">
            {t(($) => (mode === "signup" ? $.signup.title : $.signin.title))}
          </CardTitle>
          <CardDescription>
            {t(($) => (mode === "signup" ? $.signup.description : $.signin.description))}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form id="login-form" onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="login-email">{t(($) => $.common.email)}</Label>
              <Input
                id="login-email"
                type="email"
                autoComplete="email"
                placeholder={t(($) => $.common.email_placeholder)}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoFocus
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="login-password">{t(($) => $.common.password)}</Label>
              <Input
                id="login-password"
                type="password"
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
                placeholder={t(($) => $.common.password_placeholder)}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            {error && <p className="text-body text-destructive">{error}</p>}
          </form>
        </CardContent>
        <CardFooter className="flex flex-col gap-3">
          <Button
            type="submit"
            form="login-form"
            className="w-full"
            size="lg"
            disabled={!email || !password || loading}
          >
            {loading
              ? t(($) => (mode === "signup" ? $.signup.submitting : $.signin.submitting))
              : t(($) => (mode === "signup" ? $.signup.submit : $.signin.submit))}
          </Button>
          {allowSignup && (
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              onClick={() => {
                setMode((m) => (m === "signup" ? "signin" : "signup"));
                setError("");
              }}
            >
              {t(($) =>
                mode === "signup" ? $.signup.switch_to_signin : $.signin.switch_to_signup,
              )}
            </Button>
          )}
        </CardFooter>
      </Card>
    </div>
  );
}
