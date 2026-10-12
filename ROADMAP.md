# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-11
> The one roadmap of this repository. Per handbook `software/conventions/roadmap.md`: the issue tracker is the backlog, this file orders it. Shipped work is documented in its `docs/<feature>/` folder; older plans are in `docs/archive/`.

## Mission

The trusted-computing platform product and control plane: provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, attestation-gated OCI registry, DNS, tenancy and fleet ops. Imports `go-quicbaas/sdk/go` only and re-exports the composed stack (handbook `docs/00` L1, L5).

## Current milestone

[Release candidate](../../milestone/16) — target kind: RC — projected date: set by the department plan. It is the only open milestone.

## Now

- [#720](../../issues/720) — adopt the go-quicbaas v0.2.0 upstream tags ([PR #755](../../pulls/755), [PR #766](../../pulls/766)) — [docs/tenant/](docs/tenant/) — blocked: owner hold, go-xkms#1442/#1443
- [#767](../../issues/767), [#768](../../issues/768) — per-operation QUIC and default-deny gRPC authorization ([PR #769](../../pulls/769), [PR #770](../../pulls/770)) — [docs/daemon/](docs/daemon/) — blocked: go-quicbaas#1150
- [#709](../../issues/709) — EVPN/VXLAN overlay: ND suppression, IPsec control plane, gatewayd overlay service ([PR #759](../../pulls/759), [PR #762](../../pulls/762), [PR #765](../../pulls/765)) — `docs/overlay/` (to add, [#782](../../issues/782)) — in review
- [#742](../../issues/742) — deterministic EVPN session and gateway restart tests ([PR #811](../../pulls/811)) — [docs/sdn/](docs/sdn/) — in review
- [#802](../../issues/802) — Pi image assembles LUKS natively on a foreign-arch host ([PR #808](../../pulls/808)) — [docs/factory-image/](docs/factory-image/) — in review
- [#690](../../issues/690) — diskless squashfs + dm-verity root ([PR #764](../../pulls/764)) — [docs/factory-image/](docs/factory-image/) — in review
- [#691](../../issues/691) — Pi HTTP boot: the signed pipeline with a KMS-signed `boot.img`/`boot.sig`; hardware validation of the OTP burn and the EEPROM's acceptance remains, [runbook](docs/factory-image/user.md#provision-a-fleet-signed-http-boot) ([PR #761](../../pulls/761)) — [docs/ipxe/](docs/ipxe/) — blocked: owner decision pending
- [#685](../../issues/685) — Raspberry Pi network boot and bootstrap epic — [docs/ipxe/](docs/ipxe/) — open
- [#696](../../issues/696), [#771](../../issues/771) — AVR trusted firmware on trusted-firmware — [docs/firmware/](docs/firmware/) — open
- [#772](../../issues/772) — enroll a DICE AVR end to end — [docs/firmware/](docs/firmware/) — blocked: go-xkms#1441

## Next

- [#688](../../issues/688) — bootstrap.yaml platform/model/architecture fields — [docs/bootstrap/](docs/bootstrap/) — blocked: #720
- [#647](../../issues/647) — LUKS service with a real backend — `docs/luks/` (to add, [#785](../../issues/785)) — blocked: #720
- [#682](../../issues/682) — x86 TPM multi-protocol suite green and in CI — [docs/tpm/](docs/tpm/) — blocked: #720
- [#666](../../issues/666) — go-xkms canonical attestation verifier and DevID validator — [docs/attestation/](docs/attestation/) — blocked: #720
- [#175](../../issues/175), [#232](../../issues/232), [#412](../../issues/412) — one authenticated REST and MCP surface — [docs/daemon/](docs/daemon/) — blocked: go-quicbaas#1150
- [#721](../../issues/721) — tenant VRFs and the platform-services VRF — [docs/tenant/](docs/tenant/) — blocked: #709
- [#722](../../issues/722) — service layer: VIPs, placement, discovery, identity, policy — `docs/service/` (to add, in #722's own scope) — blocked: #721
- [#723](../../issues/723) — backup/restore, hitless upgrades, metrics, audit — `docs/ops/` (to add, [#834](../../issues/834)) — blocked: #722
- [#724](../../issues/724) — v0.2.0-alpha release gate: E2E, benchmarks, hardware acceptance — [docs/testing/](docs/testing/) — blocked: #723
- [#781](../../issues/781), [#783](../../issues/783), [#784](../../issues/784), [#785](../../issues/785), [#788](../../issues/788) — trust, daemon CLI, kms CLI, luks, barrier docs ([PR #806](../../pulls/806), [PR #816](../../pulls/816), [PR #812](../../pulls/812), [PR #827](../../pulls/827), [PR #822](../../pulls/822)) — [docs/daemon/](docs/daemon/), [docs/kms/](docs/kms/), `docs/trust/`, `docs/luks/`, `docs/barrier/` (to add) — in review
- [#789](../../issues/789)–[#796](../../issues/796) — feature folders for sdk, desktop-gui, gateway, bgp, platform-config, device-templates, fips, sdk-javascript — [docs/gateway/](docs/gateway/), `docs/<name>/` (to add) — open
- [#782](../../issues/782) — overlay feature folder — `docs/overlay/` (to add) — blocked: #709
- [#786](../../issues/786), [#787](../../issues/787) — security-keys and ceremony feature folders — `docs/security-keys/`, `docs/ceremony/` (to add) — blocked: PR #766
- [#756](../../issues/756), [#797](../../issues/797)–[#801](../../issues/801) — banners, feature indexes, retire `docs/cli/`, publication scrub — [docs/](docs/) — open
- [#833](../../issues/833) — spec-review scrub of `docs/` for the release candidate — [docs/](docs/) — blocked: department go (pilot verdict, slot 5)

## Later

- [#710](../../issues/710) — gateway HA state sync — blocked: the second gateway (#596)
- [#644](../../issues/644) — one user store on go-quicbaas IAM — open
- Issues off any milestone are post-RC: filter the tracker by "no milestone".
- DHT / P2P network: design only, see [docs/dht/](docs/dht/). Firmware (Android, OTA): design only, see [docs/firmware/](docs/firmware/).
- Hosted control plane: not started.

## Dependencies

- Blocker chain A: [go-qrdb#624](../../../go-qrdb/issues/624) → a go-quicbaas release → [go-quicbaas#1171](../../../go-quicbaas/issues/1171) re-exports → #720 / PR #755 → #688, #647, #682, #666.
- Sequence: #709 → #721 → #722 → #723 → #724.
- Blocker chain B: [go-quicbaas#1150](../../../go-quicbaas/issues/1150) (auth chain) → #767/#768 (PRs #769/#770), #175, #232, #412.
- Blocker chain C: [go-xkms#1442](../../../go-xkms/issues/1442), [go-xkms#1443](../../../go-xkms/issues/1443) → #755.
- Blocker chain D: [go-xkms#1441](../../../go-xkms/issues/1441) → #772.
- Down: go-recountly deployment, automatethethings.com launch, the P1 staging run.

## Non-goals

- Re-implementing go-quicbaas surfaces: see handbook `docs/00` §R.
- The P2P network beyond design.
