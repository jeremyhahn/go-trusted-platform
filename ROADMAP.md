# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-11
> The one roadmap of this repository (#780). Per handbook `software/conventions/roadmap.md`: the issue tracker is the backlog, this file orders it. Older plans are in `docs/archive/`.

## Mission

The trusted-computing platform product and control plane: provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, attestation-gated OCI registry, DNS, tenancy and fleet ops. Imports `go-quicbaas/sdk/go` only and re-exports the composed stack (handbook `docs/00` L1, L5).

## Current milestone

[Release candidate](../../milestone/16) (milestone 16). Open queue triaged 2026-10-11: about 195 open issues, 35 deliberately off the milestone as post-RC. Projected date: see the milestone.

## Complete

Each feature is documented in its folder under `docs/`; all 32 are converted. Shipped and on `main`:

- Local mode: CA/ACME, IAM, KMS, tenancy and user registration, device profiles, vTPM, EAB, attestation, bootstrap and firstboot, installer and ISO, iPXE, BMC, DNS, NTP.
- SDN and gateway: BGP multi-host fabric, the privilege-separated `gatewayd` process model, NAT64, EVPN control plane and VXLAN data plane (#709 slices A+B), tunnels (#606), IPsec through the go-xkms PKCS#11 module (#716).
- Trust: unified `pkg/trust` resolver replacing the bootstrap client; Go 1.27.2 and x/net v0.60.0 (#760); config bytes decode through the DecodeHook everywhere (#778).
- Images: Raspberry Pi factory image (#667, hardware validation pending). The nightly Pi image job is not green: the binfmt probe (#776, PR #777) and the DecodeHook (#778, PR #779) are merged, but the job now fails at LUKS under qemu-user (#802, open); it is under Now.
- Closed by triage 2026-10-11: #714/#701/#706 (superseded by #720), #705 (by #746), #16, #46, #121, #152, #165, #202, #226.

## Now

- [#720](../../issues/720) — v0.2.0-alpha on the go-quicbaas release (PR #755) — blocked: owner hold, go-xkms#1442/#1443
- [#767](../../issues/767), [#768](../../issues/768) — auth chain fixes (PRs #769, #770) — in review, blocked: go-quicbaas#1150
- [PR #764](../../pulls/764) — lands #690, in review, needs #690 PR 7
- [PR #761](../../pulls/761) (lands #691), [PR #765](../../pulls/765) (lands #709) — in review, owner decisions pending
- [PR #759](../../pulls/759) (lands #709), [PR #762](../../pulls/762) (lands #709), [PR #766](../../pulls/766) (lands #720) — in review
- [#742](../../issues/742) — deterministic gateway/BGP tests — a lane is in progress
- [#758](../../issues/758) — actionlint, trivy fail-closed — [PR #803](../../pulls/803)
- [#802](../../issues/802) — Pi image: native volume-key work; the nightly Pi image job fails at LUKS under qemu-user until it lands
- [#685](../../issues/685) — Raspberry Pi netboot epic (#688–#692) — in progress, hold-exempt
- [#696](../../issues/696), [#771](../../issues/771), [#772](../../issues/772) — trusted firmware, hold-exempt; #771 is ready, #772 is blocked on go-xkms#1441

## Next

- [#688](../../issues/688) PR 2, [#647](../../issues/647), [#682](../../issues/682), [#666](../../issues/666) — blocked: #720
- [#175](../../issues/175), [#232](../../issues/232), [#412](../../issues/412) — auth chain — blocked: go-quicbaas#1150
- [#721](../../issues/721)–[#724](../../issues/724) — v0.2.0-alpha: tenant VRFs, service layer, ops, E2E release gate
- [#780](../../issues/780)–[#801](../../issues/801) — documentation programme: one roadmap, feature folders current

## Later

- [#710](../../issues/710) — gateway HA state sync
- [#644](../../issues/644) — one user store on go-quicbaas IAM
- The 35 post-RC issues, off the milestone: filter the tracker by "no milestone".
- DHT / P2P network: design only, see `docs/dht/`. Firmware (AVR, Android, OTA): design only, see `docs/firmware/`.
- Hosted control plane: not started.

## Dependencies

- Blocker chain A: [go-qrdb#624](../../../go-qrdb/issues/624) → a go-quicbaas release → [go-quicbaas#1171](../../../go-quicbaas/issues/1171) re-exports → #720 / PR #755 → #688 PR 2, #647, #682, #666.
- Blocker chain B: [go-quicbaas#1150](../../../go-quicbaas/issues/1150) (auth chain) → #767/#768 (PRs #769/#770), #175, #232, #412.
- Blocker chain C: [go-xkms#1442](../../../go-xkms/issues/1442), [go-xkms#1443](../../../go-xkms/issues/1443) → #755.
- Down: go-recountly deployment, automatethethings.com launch, the P1 staging run.

## Non-goals

- Re-implementing go-quicbaas surfaces: see handbook `docs/00` §R.
- The P2P network beyond design.
