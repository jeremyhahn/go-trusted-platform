"use client";

/**
 * ConfigDeliveryService.GetSession and FulfillSession for the provisioning
 * session detail page (#2046, epic #1665 slice 9).
 *
 * The session is read through the SDK's DeviceService (REST
 * `GET /api/v1/provisioning/sessions/{id}`); a profile is linked through
 * `POST /api/v1/provisioning/sessions/{id}/fulfill`, which the server
 * guards with the `provisioning:write` scope. Fulfil is offered only for a
 * pending session: a fulfilled or expired one gives the reason instead.
 */
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
    throw new Error(reply.error.message || "The server refused to fulfil the session.");
  }
  return { success: true, data: { profileId: String(profileId) } };
}

export function useProvisioningSession(sessionId: string) {
  const device = useDevice();
  const query = useApi(() => device.getProvisioningSession(sessionId), [sessionId]);
  const session = query.data;
  const status = session ? provisioningSessionStatus(session) : undefined;
  const blockedReason = fulfilBlockedReason(session);

  const fulfil = useMutation<FulfilResult, ProfileCreator>(
    async (create) => {
      const reason = fulfilBlockedReason(session);
      if (reason) throw new Error(reason);
      return createProfileAndFulfil(device, sessionId, create);
    },
    {
      onSuccess: () => {
        void query.refetch();
      },
    }
  );

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
