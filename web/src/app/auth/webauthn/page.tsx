"use client";

import { useState, useEffect, Suspense, useCallback } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";
import { getBaseUrl } from "@/utils/getBaseUrl";
import { getCookie, setCookie } from "@/utils/cookie";
import { storeSession } from "@/utils/session";
import type { Session } from "@/types/session";
import styles from "./WebAuthnUI.module.css";

type AuthStatus =
  | "registered"
  | "not_registered"
  | "registering"
  | "authenticating";

interface ApiResponse<T = unknown> {
  success?: boolean;
  payload?: T;
  error?: string;
  publicKey?: PublicKeyCredentialCreationOptionsJSON &
    PublicKeyCredentialRequestOptionsJSON & { user?: { id: string } };
  session_id?: string;
}

interface TokenPayload {
  token: string;
}

interface ApiResult<T> {
  ok: true;
  data: T;
  headers: Headers;
}

interface ApiErrorResult {
  ok: false;
  error: string;
  code?: string;
  status: number;
}

type FetchResult<T> = ApiResult<T> | ApiErrorResult;

// Error codes that the backend may return
type ErrorCode =
  | "USER_NOT_FOUND"
  | "USER_EXISTS"
  | "INVALID_CREDENTIALS"
  | "CREDENTIAL_NOT_FOUND"
  | "SESSION_EXPIRED"
  | "RATE_LIMITED"
  | "VALIDATION_ERROR"
  | "INTERNAL_ERROR";

// Patterns to detect from raw error messages and map to error codes
const ERROR_PATTERNS: Array<{ pattern: RegExp; code: ErrorCode }> = [
  { pattern: /entity not found.*type=user/i, code: "USER_NOT_FOUND" },
  { pattern: /user.*not found/i, code: "USER_NOT_FOUND" },
  { pattern: /not found.*user/i, code: "USER_NOT_FOUND" },
  { pattern: /user.*exists/i, code: "USER_EXISTS" },
  { pattern: /already exists/i, code: "USER_EXISTS" },
  { pattern: /duplicate/i, code: "USER_EXISTS" },
  { pattern: /invalid.*credential/i, code: "INVALID_CREDENTIALS" },
  { pattern: /credential.*not found/i, code: "CREDENTIAL_NOT_FOUND" },
  { pattern: /no credential/i, code: "CREDENTIAL_NOT_FOUND" },
  { pattern: /session.*expired/i, code: "SESSION_EXPIRED" },
  { pattern: /token.*expired/i, code: "SESSION_EXPIRED" },
  { pattern: /rate.*limit/i, code: "RATE_LIMITED" },
  { pattern: /too many/i, code: "RATE_LIMITED" },
  { pattern: /validation/i, code: "VALIDATION_ERROR" },
  { pattern: /invalid.*input/i, code: "VALIDATION_ERROR" },
];

function detectErrorCode(rawError: string): ErrorCode | null {
  for (const { pattern, code } of ERROR_PATTERNS) {
    if (pattern.test(rawError)) {
      return code;
    }
  }
  return null;
}

async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<FetchResult<T>> {
  const baseUrl = getBaseUrl();

  try {
    const response = await fetch(`${baseUrl}${endpoint}`, {
      ...options,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...options.headers,
      },
    });

    if (!response.ok) {
      let rawError = "";
      let errorCode: string | undefined;

      try {
        const text = await response.text();
        if (text) {
          try {
            const errorData = JSON.parse(text);
            rawError = errorData.error || errorData.message || "";
            // Only use errorCode if it's a string (semantic code), not a number (HTTP status)
            const backendCode = errorData.errorCode || errorData.error_code || errorData.type;
            if (typeof backendCode === "string") {
              errorCode = backendCode;
            }
          } catch {
            rawError = text;
          }
        }
      } catch {
        // Ignore parse errors
      }

      // Detect error code from message if not provided by backend
      if (!errorCode && rawError) {
        errorCode = detectErrorCode(rawError) ?? undefined;
      }

      return {
        ok: false,
        error: rawError,
        code: errorCode,
        status: response.status,
      };
    }

    const data = await response.json();
    return { ok: true, data, headers: response.headers };
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Network request failed";
    return { ok: false, error: message, status: 0 };
  }
}

// Context-aware error messages
const CONTEXT_ERROR_MESSAGES: Record<ErrorCode, { login: string; register: string }> = {
  USER_NOT_FOUND: {
    login: "No account matched that passkey. Create an account, or try another passkey.",
    register: "Unable to start registration. Please try again.",
  },
  USER_EXISTS: {
    login: "Please enter your passkey to log in.",
    register: "An account with this email already exists. Please log in instead.",
  },
  INVALID_CREDENTIALS: {
    login: "Invalid credentials. Please try again.",
    register: "Invalid credentials. Please try again.",
  },
  CREDENTIAL_NOT_FOUND: {
    login: "No passkey found for this account. Please register a new passkey.",
    register: "No passkey found. Please complete the registration process.",
  },
  SESSION_EXPIRED: {
    login: "Your session has expired. Please try again.",
    register: "Your session has expired. Please try again.",
  },
  RATE_LIMITED: {
    login: "Too many attempts. Please wait a moment and try again.",
    register: "Too many attempts. Please wait a moment and try again.",
  },
  VALIDATION_ERROR: {
    login: "The login request was rejected. Please try your passkey again.",
    register: "Invalid input. Please check your email address and try again.",
  },
  INTERNAL_ERROR: {
    login: "Something went wrong. Please try again later.",
    register: "Something went wrong. Please try again later.",
  },
};

function getErrorMessage(result: ApiErrorResult, context: "login" | "register"): string {
  // Network errors
  if (result.status === 0) {
    return "Unable to connect to the server. Please check your connection and try again.";
  }

  // Detect error code from message
  const errorCode = result.code as ErrorCode | undefined ??
    (result.error ? detectErrorCode(result.error) : null);

  // Use context-aware message if we have a code
  if (errorCode && errorCode in CONTEXT_ERROR_MESSAGES) {
    return CONTEXT_ERROR_MESSAGES[errorCode][context];
  }

  // Fallback based on HTTP status
  if (result.status === 404) {
    return context === "login"
      ? "No account matched that passkey. Create an account, or try another passkey."
      : "Unable to start registration. Please try again.";
  }

  if (result.status === 401 || result.status === 403) {
    return "Authentication failed. Please check your credentials and try again.";
  }

  if (result.status === 409) {
    return context === "login"
      ? "Please enter your passkey to log in."
      : "An account with this email already exists. Please log in instead.";
  }

  if (result.status === 429) {
    return "Too many attempts. Please wait a moment and try again.";
  }

  if (result.status >= 500) {
    return "Something went wrong on our end. Please try again later.";
  }

  // Generic fallback - never expose raw error to user
  return context === "login"
    ? "Unable to log in. Please try your passkey again."
    : "Unable to complete registration. Please try again.";
}

function AuthStatusChecker({
  setStatus,
  setInvitationToken,
  setInvitedTenantName,
}: {
  setStatus: (status: AuthStatus) => void;
  setInvitationToken: (token: string | null) => void;
  setInvitedTenantName: (name: string | null) => void;
}) {
  const router = useRouter();
  const searchParams = useSearchParams();

  useEffect(() => {
    const jwt = getCookie("jwt");
    if (jwt) {
      router.push("/dashboard");
    } else {
      const statusParam = searchParams.get("status") as AuthStatus | null;
      if (statusParam) {
        setStatus(statusParam);
      }

      const invitation = searchParams.get("invitation");
      if (invitation) {
        setInvitationToken(invitation);
        setStatus("not_registered");

        // Optionally decode invitation to show tenant name
        // For now, we'll just show that they're being invited
        const tenantName = searchParams.get("tenant_name");
        if (tenantName) {
          setInvitedTenantName(tenantName);
        }
      }
    }
  }, [router, searchParams, setStatus, setInvitationToken, setInvitedTenantName]);

  return null;
}

export default function WebAuthnUI() {
  const [status, setStatus] = useState<AuthStatus>("registered");
  const [email, setEmail] = useState("");
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [invitationToken, setInvitationToken] = useState<string | null>(null);
  const [invitedTenantName, setInvitedTenantName] = useState<string | null>(null);

  const router = useRouter();

  const handleRegister = async () => {
    if (!email) {
      setErrorMessage("Please enter your email address.");
      return;
    }

    setLoading(true);
    setStatus("registering");
    setErrorMessage("");
    setSuccessMessage("");

    try {
      // The server reads the account address from "email"; it becomes the
      // user's login key and IAM identity (#643).
      const requestBody: { email: string; invitation_token?: string } = { email };
      if (invitationToken) {
        requestBody.invitation_token = invitationToken;
      }

      const result = await apiRequest<ApiResponse>(
        "/api/v1/webauthn/registration/begin",
        {
          method: "POST",
          body: JSON.stringify(requestBody),
        }
      );

      if (!result.ok) {
        setErrorMessage(getErrorMessage(result, "register"));
        setStatus("not_registered");
        return;
      }

      const publicKey = result.data.publicKey;
      if (!publicKey) {
        setErrorMessage("Invalid registration options returned from the server.");
        setStatus("not_registered");
        return;
      }

      const userId = publicKey.user?.id;
      if (!userId) {
        setErrorMessage("User ID not found in the registration options.");
        setStatus("not_registered");
        return;
      }

      const sessionId = result.data.session_id;
      if (!sessionId) {
        setErrorMessage("Ceremony session not found in the registration options.");
        setStatus("not_registered");
        return;
      }

      const attestationResponse = await startRegistration({ optionsJSON: publicKey });

      const verifyResult = await apiRequest<ApiResponse<TokenPayload>>(
        "/api/v1/webauthn/registration/finish",
        {
          method: "POST",
          body: JSON.stringify(attestationResponse),
          headers: { "X-User-Id": userId, "X-Session-Id": sessionId },
        }
      );

      if (!verifyResult.ok) {
        setErrorMessage(getErrorMessage(verifyResult, "register"));
        setStatus("not_registered");
        return;
      }

      // Handle both formats: payload as string (JWT) or payload as {token: string}
      const jwt = typeof verifyResult.data.payload === "string"
        ? verifyResult.data.payload
        : verifyResult.data.payload?.token;

      if (jwt) {
        setCookie("jwt", jwt, {
          expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          secure: true,
          sameSite: "Strict",
        });
        setSuccessMessage("Registration successful!");
        router.push("/dashboard");
      } else {
        setErrorMessage("Registration failed. Please try again.");
        setStatus("not_registered");
      }
    } catch (err) {
      console.error("Registration Error:", err);
      setErrorMessage(
        err instanceof Error ? err.message : "An unexpected error occurred."
      );
      setStatus("not_registered");
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async () => {
    // No username: the ceremony uses discoverable credentials, so the
    // authenticator identifies the user and the server resolves them from
    // the credential id it returns. Nothing is looked up beforehand.
    setLoading(true);
    setStatus("authenticating");
    setErrorMessage("");
    setSuccessMessage("");

    try {
      const result = await apiRequest<ApiResponse>(
        "/api/v1/webauthn/login/begin",
        { method: "POST" }
      );

      if (!result.ok) {
        setErrorMessage(getErrorMessage(result, "login"));
        setStatus("registered");
        return;
      }

      const publicKey = result.data.publicKey;
      if (!publicKey) {
        setErrorMessage("Invalid authentication options returned from the server.");
        setStatus("registered");
        return;
      }

      const sessionId = result.data.session_id;
      if (!sessionId) {
        setErrorMessage("Ceremony session not found in the authentication options.");
        setStatus("registered");
        return;
      }

      const assertionResponse = await startAuthentication({ optionsJSON: publicKey });

      const verifyResult = await apiRequest<ApiResponse<Session>>(
        "/api/v1/webauthn/login/finish",
        {
          method: "POST",
          body: JSON.stringify(assertionResponse),
          headers: { "X-Session-Id": sessionId },
        }
      );

      if (!verifyResult.ok) {
        setErrorMessage(getErrorMessage(verifyResult, "login"));
        setStatus("registered");
        return;
      }

      const session = verifyResult.data.payload;
      if (verifyResult.data.success && session?.bearer) {
        storeSession(session);
        setSuccessMessage("Login successful!");
        router.push("/dashboard");
      } else {
        setErrorMessage("Login failed. Please try again.");
        setStatus("registered");
      }
    } catch (err) {
      console.error("Login Error:", err);
      setErrorMessage(
        err instanceof Error ? err.message : "An unexpected error occurred."
      );
      setStatus("registered");
    } finally {
      setLoading(false);
    }
  };

  const setStatusCallback = useCallback((s: AuthStatus) => setStatus(s), []);
  const setInvitationTokenCallback = useCallback((token: string | null) => setInvitationToken(token), []);
  const setInvitedTenantNameCallback = useCallback((name: string | null) => setInvitedTenantName(name), []);

  return (
    <Suspense fallback={<div>Loading...</div>}>
      <AuthStatusChecker
        setStatus={setStatusCallback}
        setInvitationToken={setInvitationTokenCallback}
        setInvitedTenantName={setInvitedTenantNameCallback}
      />

      <div className={styles.container}>
        <div className={styles.card}>
          {status === "not_registered" && (
            <>
              <h2 className={styles.title}>
                {invitationToken ? "Join Workspace" : "Create Account"}
              </h2>
              <p className={styles.message}>
                {invitationToken && invitedTenantName
                  ? `You've been invited to join ${invitedTenantName}. `
                  : invitationToken
                  ? "You've been invited to join a workspace. "
                  : "Create your account and workspace. "}
                This service supports only WebAuthn/FIDO2 passkeys to ensure the
                highest level of privacy and security.
              </p>
              {errorMessage && (
                <p className={styles.errorMessage}>{errorMessage}</p>
              )}
              {successMessage && (
                <p className={styles.successMessage}>{successMessage}</p>
              )}
              <input
                type="email"
                autoComplete="email"
                aria-label="Email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className={styles.inputField}
              />
              <button
                onClick={handleRegister}
                disabled={loading}
                className={styles.button}
              >
                {loading ? "Registering..." : "Register"}
              </button>
              <p
                onClick={() => setStatus("registered")}
                className={styles.clickableText}
              >
                Already have an account? Log In
              </p>
            </>
          )}

          {status === "registered" && (
            <>
              <h2 className={styles.title}>Login</h2>
              <p className={styles.message}>
                Use your passkey to log in securely.
              </p>
              {errorMessage && (
                <p className={styles.errorMessage}>{errorMessage}</p>
              )}
              {successMessage && (
                <p className={styles.successMessage}>{successMessage}</p>
              )}
              {/*
                No username field. Login is usernameless: the authenticator
                picks the credential and the server resolves the account from
                it, so handleLogin sends nothing typed here. Leaving the input
                in place was worse than redundant — someone could type one
                account name, be signed in as another by the authenticator's
                own picker, and have the UI imply the name they typed had
                constrained it. Registration keeps the field, because that is
                where the account is named.
              */}
              <button
                onClick={handleLogin}
                disabled={loading}
                className={styles.button}
              >
                {loading ? "Authenticating..." : "Log In"}
              </button>
              <p
                onClick={() => setStatus("not_registered")}
                className={styles.clickableText}
              >
                Don&apos;t have an account? Register
              </p>
            </>
          )}

          {status === "registering" && (
            <p className={styles.message}>
              Registering... Please follow the instructions.
            </p>
          )}
          {status === "authenticating" && (
            <p className={styles.message}>
              Authenticating... Please follow the instructions.
            </p>
          )}
        </div>
      </div>
    </Suspense>
  );
}
