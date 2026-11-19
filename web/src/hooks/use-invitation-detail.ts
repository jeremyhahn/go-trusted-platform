'use client';

import { useApi, useInvitation } from 'trusted-platform-sdk';
import type { Invitation, InvitationStatus, UseApiResult } from 'trusted-platform-sdk';

/**
 * An invitation as the REST endpoint emits it: camelCase or snake_case keys,
 * and the status as an enum name such as "INVITATION_STATUS_PENDING" (#445).
 */
export interface InvitationWire {
  id?: string;
  token?: string;
  email?: string;
  role?: string;
  status?: string;
  tenantId?: string;
  tenant_id?: string;
  tenantName?: string;
  tenant_name?: string;
  expiresAt?: string;
  expires_at?: string;
  createdAt?: string;
  created_at?: string;
  acceptedAt?: string;
  accepted_at?: string;
  invitedById?: string;
  invited_by_id?: string;
}

/** The invitation fields the detail and accept pages show. */
export interface InvitationView {
  id: string;
  email: string;
  role: string;
  status: InvitationStatus;
  tenantId: string;
  tenantName: string;
  expiresAt: string;
  createdAt: string;
  acceptedAt: string;
  invitedById: string;
}

function normalizeStatus(raw: string | undefined): InvitationStatus {
  const s = String(raw || '').toUpperCase();
  if (s.endsWith('ACCEPTED')) return 'accepted';
  if (s.endsWith('REVOKED') || s.endsWith('CANCELLED')) return 'revoked';
  if (s.endsWith('EXPIRED')) return 'expired';
  return 'pending';
}

/**
 * Normalizes a get or get-by-token response: the invitation sits at
 * `.invitation` or is the payload itself.
 */
export function toInvitationView(response: unknown): InvitationView | null {
  if (!response || typeof response !== 'object') return null;
  const envelope = response as { invitation?: InvitationWire } & InvitationWire;
  const inv: InvitationWire = envelope.invitation ?? envelope;
  if (!inv.id && !inv.email) return null;
  return {
    id: inv.id ?? '',
    email: inv.email ?? '',
    role: inv.role ?? 'member',
    status: normalizeStatus(inv.status),
    tenantId: inv.tenantId ?? inv.tenant_id ?? '',
    tenantName: inv.tenantName ?? inv.tenant_name ?? '',
    expiresAt: inv.expiresAt ?? inv.expires_at ?? '',
    createdAt: inv.createdAt ?? inv.created_at ?? '',
    acceptedAt: inv.acceptedAt ?? inv.accepted_at ?? '',
    invitedById: inv.invitedById ?? inv.invited_by_id ?? '',
  };
}

/** Fetches one invitation by id (GetInvitation). */
export function useInvitationById(id: string): UseApiResult<{ invitation: Invitation }> {
  const { service } = useInvitation();
  return useApi(() => service.get(id), [id], { enabled: id !== '' });
}

/** Fetches the invitation a token names (GetInvitationByToken). */
export function useInvitationByToken(token: string): UseApiResult<{ invitation: Invitation }> {
  const { service } = useInvitation();
  return useApi(() => service.getByToken(token), [token], { enabled: token !== '' });
}
