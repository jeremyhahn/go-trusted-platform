# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Per handbook `software/conventions/roadmap.md`: the Software Department refreshes it; the project agent proposes changes by PR.

## Mission

The trusted-computing platform product and control plane: provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, attestation-gated OCI registry, DNS, tenancy and fleet ops. Imports `go-quicbaas/sdk/go` only and re-exports the composed stack (handbook `docs/00` L1, L5).

## Current milestone

`Public release` milestone (M16): 88 open, 1 closed. Release candidate projected **2027-01-21** through go-signal and go-quicbaas, or **2026-11-20** on its own throughput. The agent's v0.2.0-alpha plan (#720–#724) runs outside the milestone; folding it in is the first roadmap PR.

## Now

- #742 — gateway process and BGP tests deterministic; main green — open
- #714 — on go-quicbaas v0.13.1-alpha — open
- #720 — on go-quicbaas v0.14 — blocked: go-quicbaas#1155 tag
- #165 — no REST route reachable without a credential (critical) — blocked
- #121 — seeder routes authenticate the caller (critical) — blocked
- #304 — resource:action permissions on 357 MCP tools (critical) — in progress
- #704 — full go-quicbaas surface re-exported (G7) — open
- #746 — go-luks2 v1.0.0-rc.2 adopted — open

## Next

- #213 — logout revokes the server session — blocked
- #232 — no second unauthenticated REST server — open
- #238 — PXE completion webhook authenticates — blocked
- #33 — daemon mTLS key not written to /tmp — blocked
- #34 — every test package runs in a CI stage — open
- #71 — release recipe fixed — open
- #226 — attestation reporting service complete — open

## Later

- #721–#724 — v0.2.0-alpha: tenant VRFs, service layer, ops, E2E release gate
- #709, #710 — EVPN/VXLAN overlay, gateway HA state sync
- #644 — one user store on go-quicbaas IAM

## Dependencies

- Up: go-quicbaas v0.12.0-alpha (latest tag v0.13.1-alpha; v0.14.0-alpha untagged). The direct residue pins are `docs/18` V5.
- Down: go-recountly deployment (Infrastructure), automatethethings.com launch, the P1 staging run.

## Non-goals

- Re-implementing go-quicbaas surfaces: volumes and the coordinator live in go-quicbaas#195 (gtp #90/#91 re-scoped).
- The P2P network: design only.
