# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-14
> The one roadmap of this repository. [docs/SPEC.md](docs/SPEC.md) specifies the features; this file orders them and names each by its SPEC table name. The issue tracker is the backlog. Older plans are in `docs/archive/`.

## Mission

The trusted-computing platform product and control plane: provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, attestation-gated OCI registry, DNS, tenancy and fleet ops. Layer 5 of the stack, one product in layers: it embeds go-quicbaas as a library, and only go-quicbaas, and re-exports through `sdk/go` every go-quicbaas service, with the go-qrdb database and go-xkms hardware crypto services beneath it, adding its platform services on top. One cluster engine and one datastore per deployment, go-qrdb's; no store, service or client of its own for something a lower layer provides.

## Milestones

- [Release candidate](../../milestone/16), due 2026-11-23, 77 open / 107 closed: public release (R4); the version is confirmed at the owner's publish approval. It closes when the [SPEC release criteria](docs/SPEC.md#release-criteria) hold; the v0.2.0-alpha gate is #724.
- Issues off any milestone are post-RC.
- Waiting on the release candidate: the go-recountly deployment, the automatethethings.com launch, the P1 staging run.

## Complete

- **barrier** — shipped in v0.1.0-alpha; feature folder #788 and init-only gate #823 (PR #822) — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **bmc** — shipped in v0.1.0-alpha, with #104 and #105 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **ca** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **cluster** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **compute** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **device** — shipped in v0.1.0-alpha; heartbeat liveness #150, enable/disable #250, one device contract #484 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **dns** — shipped in v0.1.0-alpha; DNS64 #615 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **eab** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **health** — shipped in v0.1.0-alpha, with #221 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **iam** — shipped in v0.1.0-alpha, with #151, #159 and #401 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **ima** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **kms** — shipped in v0.1.0-alpha, with #784 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **ntp** — shipped in v0.1.0-alpha, with #514 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **provisioning** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **proxy** — shipped in v0.1.0-alpha; YAML configuration and a persistent store #570 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **registry** — shipped in v0.1.0-alpha, with #549 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **sdn** — shipped in v0.1.0-alpha; reference network #708 (PR #729); EVPN control plane and VXLAN data plane (PR #754) — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **secrets** — shipped in v0.1.0-alpha, with #699 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **security** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **switch** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **tpm** — shipped in v0.1.0-alpha, with #471 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **trust** — shipped in v0.1.0-alpha; platform anchor and resolver #653 (PR #698) — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **vtpm** — shipped in v0.1.0-alpha — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **web** — shipped in v0.1.0-alpha, with #428 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **avr-attestation** — the AVR attestation provider; it reaches the devices through the go-quicbaas SDK, which composes trusted-firmware's `xkms` adapter into go-xkms — [PR #700](../../pulls/700) — done
- **sdk-javascript** — shipped in v0.1.0-alpha, with #211 and #231 — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done

## Now

- **ipxe** — Raspberry Pi netboot on real hardware; Phases 0, 1 and 2A landed (PR #719), Phase 4 (PR #764), Phase 5 software (PR #761) — [#685](../../issues/685) — open
- **ipxe** — Phase 2: per-node bootstrap.yaml fields and orchestrator — [#688](../../issues/688) — open
- **ipxe** — Phase 3: diskless NBD-over-TLS — [#689](../../issues/689) — open
- **ipxe** — Phase 5 hardware validation (OTP burn, EEPROM acceptance) and Phase 6 hardware runbook — [#692](../../issues/692) — open
- **ipxe** — install-completion webhook authentication — [#238](../../issues/238) — open
- **gateway** — the network edge replaces the edge routers — [#553](../../issues/553) — open
- **gateway** — EVPN/VXLAN overlay; the gatewayd overlay service landed (PR #765) — [#709](../../issues/709) — open
- **gateway** — process model, with #657 — [#557](../../issues/557) — open
- **gateway** — gateway ops — [#65](../../issues/65) — open
- **gateway** — load-balancer, perf and NAT64 wiring — [#660](../../issues/660) — open
- **gateway** — secret-store identity and scheme, with #659 — [#658](../../issues/658) — open
- **factory-image** — Raspberry Pi factory image (PR #680) — [#667](../../issues/667) — open
- **factory-image** — diskless squashfs + dm-verity root (PR #764) — [#690](../../issues/690) — done
- **factory-image** — measurement manifest per signed image in the go-quicbaas reference-values store (blocked by the go-quicbaas tag that carries [go-xkms#1443](../../../go-xkms/issues/1443) step 3) — [#720](../../issues/720) — blocked: waits on the go-quicbaas tag
- **firmware** — AVR support on trusted-firmware, the device reached through the go-quicbaas SDK, which composes trusted-firmware's `xkms` adapter into go-xkms; provider landed (PR #700) — [#771](../../issues/771) — open
- **device-enrollment** — AVR enrollment, device registry and gateway relay, the device reached through the go-quicbaas SDK — [#696](../../issues/696) — open
- **device-enrollment** — DICE AVR end to end, the device reached through the go-quicbaas SDK — [#772](../../issues/772) — open
- **sdk** — full composed go-quicbaas re-export; agentic re-exports merged in trains #876 and #878 — [#704](../../issues/704) — open
- **sdk** — SDK and server routes agree — [#452](../../issues/452) — open
- **vpn** — attested remote-access VPN: admission control plane and both data planes landed (PR #611); the multi-protocol surface, CLI and client agent remain — [#584](../../issues/584) — open

## Next

- **attestation** — the go-quicbaas SDK's peer verifier, `xkms.NewPeerAttestationVerifier` in the `sdk/go/xkms` re-export from go-xkms, replaces the VM verifier and the DevID validator — [#666](../../issues/666) — open
- **attestation** — the device quote verifier uses that same SDK attested-peer primitive — [#482](../../issues/482) — open
- **attestation** — admission status source — [#715](../../issues/715) — open
- **attestation** — parity and production wiring, with #498 and #386 — [#545](../../issues/545) — open
- **attestation** — expected PCR values from the go-quicbaas reference-values store, replacing the `PCRBaseline` table and the `GoldenValues` policy surface (blocked by the go-quicbaas tag that carries [go-xkms#1443](../../../go-xkms/issues/1443) step 3) — [#720](../../issues/720) — blocked: waits on the go-quicbaas tag
- **auth** — no user store of the platform's own, users held in go-quicbaas IAM, the stack's one user store — [#644](../../issues/644) — open
- **auth** — login, logout, mTLS sign-in and backbone sessions, with #213, #199 and #662 — [#640](../../issues/640) — open
- **auth** — hardware enrollment check — [#281](../../issues/281) — open
- **bootstrap** — FIPS Noise bootstrap listener — [#518](../../issues/518) — open
- **bootstrap** — seeder over mTLS — [#176](../../issues/176) — open
- **daemon** — per-operation QUIC authorization (PR #769) — [#767](../../issues/767) — done
- **daemon** — default-deny gRPC authorization (PR #770) — [#768](../../issues/768) — done
- **daemon** — ops: backup/restore, hitless upgrades, metrics/SLOs, audit, switch render — [#723](../../issues/723) — blocked: waits on #722
- **daemon** — one authenticated REST surface, with #232 — [#175](../../issues/175) — open
- **daemon** — MCP permissions, with #304 and #538 — [#412](../../issues/412) — open
- **daemon** — identity renewal — [#36](../../issues/36) — open
- **daemon** — dead transport handlers — [#317](../../issues/317) — open
- **daemon** — `--setuid` — [#349](../../issues/349) — open
- **daemon** — FailedPrecondition mapping — [#665](../../issues/665) — open
- **installer** — signed ISO kernel and initrd — [#354](../../issues/354) — open
- **installer** — required build inputs — [#351](../../issues/351) — open
- **installer** — root seal on `luks-root` from `seal-pcrs` and offline unseal from the `.tpmpolicy` binding record (blocked by the go-quicbaas tag that carries [go-xkms#1443](../../../go-xkms/issues/1443) step 3) — [#720](../../issues/720) — blocked: waits on the go-quicbaas tag
- **luks** — real backend — [#647](../../issues/647) — open
- **luks** — go-luks2 v1.0.0-rc.2 — [#746](../../issues/746) — open
- **luks** — FIPS activation restrictions — [#26](../../issues/26) — open
- **luks** — upgrade by staging a signed image and confirm after boot (blocked by the go-quicbaas tag that carries [go-xkms#1443](../../../go-xkms/issues/1443) step 3) — [#720](../../issues/720) — blocked: waits on the go-quicbaas tag
- **tenant** — tenant VRFs and the platform-services VRF — [#721](../../issues/721) — blocked: waits on #709
- **tenant** — owner-invitation route — [#299](../../issues/299) — open
- **gateway** — service layer: VIPs, placement, discovery, identity, policy — [#722](../../issues/722) — blocked: waits on #721
- **gateway** — the second gateway — [#596](../../issues/596) — open
- **gateway** — HA state sync, after the second gateway — [#710](../../issues/710) — open

## Later

- **volume** — go-blockstore adapter — [#90](../../issues/90) — open
- **volume** — volume coordination on go-qrdb's volume pools through the go-quicbaas SDK, with no coordinator of the platform's own — [#91](../../issues/91) — open
- **volume** — volume-mount attestation gate, container volumes, live migration and NFS root — [#92](../../issues/92) — open
- **remote-deploy** — remote agent deploy over QUIC, replacing SSH — [#54](../../issues/54) — open
- **pi-node-roles** — control-plane, compute and gateway templates for raspberrypi: rpi4 first, rpi5 experimental, the 3B+ as standalone compute only if its 1 GB proves enough — [Raspberry Pi templates](configs/platform/templates/dedicated/raspberrypi/README.md) — open
- **ha-raft-template** — the three-node control plane the templates README lists as Planned — [configs/platform/templates/README.md](configs/platform/templates/README.md) — open

## Future

- **dht** — trusted DHT for the public peer-to-peer hosting platform; design only — [docs/dht/](docs/dht/) — open
- **android-ota** — Android and secure OTA updates; design only — [docs/firmware/android.md](docs/firmware/android.md) — open
- **hosted-control-plane** — hosted control plane; not started — [SPEC Features](docs/SPEC.md#features) — open
- **hsm-device-lifecycle** — provisioning and attestation of HSM devices, the NXP FRDM-IMX95-PRO first; the board's Linux image is built by trusted-imx95, not here; not started — [#884](../../issues/884) — open
- **jetson-orin-node** — NVIDIA Jetson Orin as a robotics compute node, provisioned and attested through UEFI Secure Boot and the firmware TPM, the Raspberry Pi node lifecycle; not started — [SPEC Features](docs/SPEC.md#features) — blocked: waits for a borrowed unit

## Dependencies

- **tpm** — [go-quicbaas#1171](../../../go-quicbaas/issues/1171) re-exports in a go-quicbaas release, plus [go-xkms#1442](../../../go-xkms/issues/1442) and [go-xkms#1443](../../../go-xkms/issues/1443) → #720 → #682. [go-quicbaas#1171](../../../go-quicbaas/issues/1171) → **ipxe** #688.
- **installer**, **luks**, **factory-image**, **attestation** — unattended unlock across kernel updates: [go-xkms#1443](../../../go-xkms/issues/1443) steps 1 and 2 tagged → the go-quicbaas tag that carries step 3 (`Security().TPMPolicy()` and the initrd re-exports in `sdk/go/xkms`) → step 4 (installer seal and initrd unseal, attestation reference values) → step 5 (factory-image manifest, luks staging and confirm) → the owner's SPEC change that retires TPM-Upgrade, `seal-upgrade.*` and the on-device rebuild.
- **pi-node-roles** — a go-qrdb arm64 release → Pi control-plane nodes.
- **daemon** — [go-quicbaas#1150](../../../go-quicbaas/issues/1150) → one authenticated REST and MCP surface #175, #232, #412.
- **gateway** #709 → **tenant** #721 → **gateway** #722 → **daemon** #723 → the v0.2.0-alpha gate #724.
- **gateway** — the second gateway #596 → HA state sync #710.
- **avr-attestation** — the go-quicbaas release that composes trusted-firmware's `xkms` adapter into go-xkms; the platform depends on no trusted-firmware module.
- **device-enrollment** — collects the DICE evidence through the go-quicbaas SDK, which composes trusted-firmware's `xkms` adapter into go-xkms, and verifies it through the go-quicbaas SDK's DICE evidence verification (not yet published), re-exported from go-xkms; no version is consumed yet. Registration waits on [trusted-firmware#28](../../../trusted-firmware/issues/28) (phases B and C) and the go-quicbaas release on the go-xkms hook tag that composes the adapter → #771 → #772.
