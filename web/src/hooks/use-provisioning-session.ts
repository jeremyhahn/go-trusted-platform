"use client";

/**
 * ConfigDeliveryService.GetSession and FulfillSession for the provisioning
 * session detail page (#2046, epic #1665 slice 9).
 *
 * The session is read through the SDK's DeviceService (REST
 * `GET /api/v1/provisioning/sessions/{id}`); a profile is linked through
 * `POST /api/v1/provisioning/sessions/{id}/fulfill`, which the server
 * guards with the `provisioning:write` scope. Fulfil is offered only for a
 * pending session and a signed-in admin: otherwise, or after a 403 from
 * fulfil, the hook gives the reason instead.
 */
import { useRef } from "react";
import { useOptionalAuth } from "@/contexts/AuthContext";
import {
  useApi,
  useDevice,
  useMutation,
  type ApiResponse,
  type FulfillSessionRequest,
  type ProvisioningSession,
} from "trusted-platform-sdk";

export type ProvisioningSessionStatus = "pending" | "fulfilled" | "expired";

/** Creates the profile to link and resolves to its id (undefined if none). */
export type ProfileCreator = () => Promise<string | null | undefined>;

export interface FulfilResult {
  profileId: string;
}

interface SessionFulfiller {
  fulfillProvisioningSession(request: FulfillSessionRequest): Promise<ApiResponse<void>>;
}

export function provisioningSessionStatus(
  session: ProvisioningSession,
  now: Date = new Date()
): ProvisioningSessionStatus {
  if (session.fulfilled) return "fulfilled";
  if (new Date(session.expires_at) < now) return "expired";
  return "pending";
}

/** Why the session cannot be fulfilled now, or null when it can. */
export function fulfilBlockedReason(
  session: ProvisioningSession | undefined,
  now: Date = new Date()
): string | null {
  if (!session) return "The session is not loaded.";
  switch (provisioningSessionStatus(session, now)) {
    case "fulfilled":
      return "The session is already fulfilled.";
    case "expired":
      return "The session has expired; the device must restart provisioning.";
    default:
      return null;
  }
}

/**
 * Creates the profile, then fulfils the session with its id. A missing
 * profile id or a fulfil refusal from the server throws, so the caller never
 * reports a fulfilled session the server did not fulfil.
 */
export async function createProfileAndFulfil(
  device: SessionFulfiller,
  sessionId: string,
  create: ProfileCreator
): Promise<ApiResponse<FulfilResult>> {
  const profileId = await create();
  if (!profileId) {
    throw new Error("The server returned no profile id; the session was not fulfilled.");
  }
  const reply = await device.fulfillProvisioningSession({
    session_id: sessionId,
    profile_id: String(profileId),
  });
  if (reply?.error !== undefined) {
    // Keep the server's code and status so a 403 can gate the controls.
    const { code, status } = reply.error as { code?: unknown; status?: unknown };
    throw Object.assign(
      new Error(reply.error.message || "The server refused to fulfil the session."),
      { code: code === undefined ? "FULFIL_REFUSED" : String(code), status }
    );
  }
  return { success: true, data: { profileId: String(profileId) } };
}

/** Variables of the fulfil mutation: an object, never a bare function. */
export interface FulfilVariables {
  create: ProfileCreator;
}

/**
 * The server serves fulfil on its admin gate with the `provisioning:write`
 * scope (pkg/webservice/v1/router/device.go). No capability source exists
 * yet, so the console gates on what the session carries: the admin role.
 */
export const FULFIL_ROLE = "admin";
export const FULFIL_ROLE_REASON =
  "Fulfilling a session needs the admin role and the provisioning:write scope";

/** Why the signed-in user cannot fulfil, or null when the role allows it. */
export function fulfilAccessReason(roles: readonly string[] | null | undefined): string | null {
  return roles?.includes(FULFIL_ROLE) ? null : FULFIL_ROLE_REASON;
}

/** The server's message when a fulfil reply was a 403, otherwise null. */
export function fulfilForbiddenReason(error: unknown): string | null {
  if (error === null || typeof error !== "object") return null;
  const { status, code, message } = error as { status?: unknown; code?: unknown; message?: unknown };
  if (status !== 403 && code !== "FORBIDDEN") return null;
  return typeof message === "string" && message !== "" ? message : FULFIL_ROLE_REASON;
}

export function useProvisioningSession(sessionId: string) {
  const device = useDevice();
  const auth = useOptionalAuth();
  const query = useApi(() => device.getProvisioningSession(sessionId), [sessionId]);
  const session = query.data;
  const status = session ? provisioningSessionStatus(session) : undefined;
  const accessReason = fulfilAccessReason(auth?.user?.roles);
  // A 403 from fulfil is kept so a retry cannot create another profile.
  const forbiddenRef = useRef<string | null>(null);

  const fulfil = useMutation<FulfilResult, FulfilVariables>(
    async ({ create }) => {
      const reason = fulfilBlockedReason(session) ?? accessReason ?? forbiddenRef.current;
      if (reason) throw new Error(reason);
      return createProfileAndFulfil(device, sessionId, create);
    },
    {
      onSuccess: () => {
        void query.refetch();
      },
      onError: (error) => {
        const forbidden = fulfilForbiddenReason(error);
        if (forbidden) forbiddenRef.current = forbidden;
      },
    }
  );

  const blockedReason =
    fulfilBlockedReason(session) ?? accessReason ?? fulfilForbiddenReason(fulfil.error);

  return {
    session,
    isLoading: query.isLoading,
    error: query.error,
    refetch: query.refetch,
    status,
    fulfilBlockedReason: blockedReason,
    fulfil,
  };
}
