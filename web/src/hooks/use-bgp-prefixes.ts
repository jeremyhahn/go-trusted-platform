"use client";

/**
 * BGP peers and announced prefixes on the gateway (#2051).
 *
 * ListBGPPeers, AnnouncePrefix and WithdrawPrefix are served under
 * `/api/v1/gateway/bgp` (pkg/webservice/v1/rest/gateway/router.go):
 * `GET /bgp/peers`, `POST /bgp/prefixes`, `GET /bgp/prefixes` and
 * `DELETE /bgp/prefixes?prefix=<cidr>`. The hook calls the SDK
 * GatewayService from `useGateway()`, never a hand-written fetch.
 *
 * Withdrawing a prefix stops advertising it to every peer, so a control
 * that calls `withdraw` must confirm first.
 */

import { useMemo } from "react";
import { useGateway } from "trusted-platform-sdk";

/** A BGP peer as the SDK's ListBGPPeersResponse carries it (the SDK root does not export BGPPeer). */
export interface BGPPeer {
  address: string;
  asn: number;
  state: string;
  description?: string;
  prefixesReceived: number;
  prefixesSent: number;
  uptime?: string;
}

/** Peers whose state is not "ESTABLISHED" (case-insensitive), in input order. */
export function peersDown(peers: BGPPeer[]): BGPPeer[] {
  return peers.filter((p) => p.state.toUpperCase() !== "ESTABLISHED");
}

const IPV4_ADDR = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6_ADDR = /^[0-9a-fA-F:.]+$/;
const PREFIX_LEN = /^\d{1,3}$/;

/** Trimmed CIDR when it looks like `<addr>/<len>` (IPv4 len 0-32 or IPv6 len 0-128, a ':' marks IPv6), else null. No DNS, no address arithmetic. */
export function normalizePrefix(input: string): string | null {
  const cidr = input.trim();
  const slash = cidr.indexOf("/");
  if (slash <= 0 || slash !== cidr.lastIndexOf("/")) return null;
  const addr = cidr.slice(0, slash);
  const len = cidr.slice(slash + 1);
  if (!PREFIX_LEN.test(len)) return null;
  const bits = Number(len);
  if (addr.includes(":")) {
    return IPV6_ADDR.test(addr) && bits <= 128 ? cidr : null;
  }
  return IPV4_ADDR.test(addr) && bits <= 32 ? cidr : null;
}

/** BGP operations on the SDK GatewayService. */
export function useBGPPrefixes() {
  const gateway = useGateway();
  return useMemo(
    () => ({
      listPeers: () => gateway.listBGPPeers(),
      listAnnounced: () => gateway.listAnnouncedPrefixes(),
      announce: (prefix: string, nextHop?: string) =>
        gateway.announcePrefix(
          nextHop?.trim() ? { prefix: prefix.trim(), nextHop: nextHop.trim() } : { prefix: prefix.trim() }
        ),
      withdraw: (prefix: string) => gateway.withdrawPrefix({ prefix: prefix.trim() }),
    }),
    [gateway]
  );
}
