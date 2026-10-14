# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-13
> The one roadmap of this repository. [docs/SPEC.md](docs/SPEC.md) specifies the features; this file orders them and names each by its SPEC table name. The issue tracker is the backlog. Older plans are in `docs/archive/`.

## Mission

The trusted-computing platform product and control plane: provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, attestation-gated OCI registry, DNS, tenancy and fleet ops. Imports `go-quicbaas/sdk/go` only and re-exports the composed stack.

## Milestones

- [Release candidate](../../milestone/16), due 2026-11-23, 77 open / 107 closed: public release (R4); the version is confirmed at the owner's publish approval. It closes when [SPEC §5](docs/SPEC.md#5-release-criteria) holds; the v0.2.0-alpha gate is #724.
- Issues off any milestone are post-RC.
- Waiting on the release candidate: the go-recountly deployment, the automatethethings.com launch, the P1 staging run.

## Complete

- **barrier** — v0.1.0-alpha; feature folder #788 and init-only gate #823 (PR #822)
- **bmc** — v0.1.0-alpha; #104, #105
- **ca** — v0.1.0-alpha
- **cluster** — v0.1.0-alpha
- **compute** — v0.1.0-alpha
- **device** — v0.1.0-alpha; heartbeat liveness #150; enable/disable #250; one device contract #484
- **dns** — v0.1.0-alpha; DNS64 #615
- **eab** — v0.1.0-alpha
- **health** — v0.1.0-alpha; #221
- **iam** — v0.1.0-alpha; #151, #159, #401
- **ima** — v0.1.0-alpha
- **kms** — v0.1.0-alpha; #784
- **ntp** — v0.1.0-alpha; #514
- **provisioning** — v0.1.0-alpha
- **proxy** — v0.1.0-alpha; YAML configuration and a persistent store #570
- **registry** — v0.1.0-alpha; #549
- **sdn** — v0.1.0-alpha; reference network #708 (PR #729); EVPN control plane and VXLAN data plane (PR #754)
- **secrets** — v0.1.0-alpha; #699
- **security** — v0.1.0-alpha
- **switch** — v0.1.0-alpha
- **tpm** — v0.1.0-alpha; #471
- **trust** — v0.1.0-alpha; platform anchor and resolver #653 (PR #698)
- **vtpm** — v0.1.0-alpha
- **web** — v0.1.0-alpha; #428
- **avr-attestation** — the AVR attestation provider (PR #700), on trusted-firmware sdk/go v0.3.0-alpha (train #874)
- **sdk-javascript** — v0.1.0-alpha; #211, #231

### Closed issues on features still in progress

- **daemon** — per-operation QUIC authorization #767 (PR #769); default-deny gRPC authorization #768 (PR #770); its open work is in Next
- **factory-image** — diskless squashfs + dm-verity root #690 (PR #764); its open work is in Now

## Now

- **ipxe** — Raspberry Pi netboot on real hardware #685: Phase 2 per-node bootstrap.yaml fields and orchestrator #688, Phase 3 diskless NBD-over-TLS #689, Phase 5 hardware validation (OTP burn, EEPROM acceptance), Phase 6 hardware runbook #692 (Phases 0, 1 and 2A landed, PR #719; Phase 4 PR #764; Phase 5 software PR #761); install-completion webhook authentication #238
- **gateway** — the network edge replaces the edge routers #553: EVPN/VXLAN overlay #709 (gatewayd overlay service landed, PR #765); process model #557, #657; gateway ops #65; load-balancer, perf and NAT64 wiring #660; secret-store identity and scheme #658, #659
- **factory-image** — Raspberry Pi factory image #667 (PR #680)
- **firmware** — AVR support on trusted-firmware #771 (provider landed, PR #700; trusted-firmware sdk/go migration merged in train #874)
- **device-enrollment** — AVR enrollment, device registry and gateway relay #696; DICE AVR end to end #772
- **sdk** — full composed go-quicbaas re-export #704 (agentic re-exports merged in trains #876 and #878); SDK and server routes agree #452
- **vpn** — attested remote-access VPN #584: admission control plane and both data planes landed (PR #611); the multi-protocol surface, CLI and client agent remain

## Next

- **attestation** — go-xkms canonical verifier #666 and the upstream attested-peer primitive #482; admission status source #715; parity and production wiring #545, #498, #386
- **auth** — one user store on go-quicbaas IAM #644; login, logout, mTLS sign-in and backbone sessions #640, #213, #199, #662; hardware enrollment check #281
- **bootstrap** — FIPS Noise bootstrap listener #518; seeder over mTLS #176
- **daemon** — ops: backup/restore, hitless upgrades, metrics/SLOs, audit, switch render #723 (blocked by #722); one authenticated REST surface #175, #232 and MCP permissions #412, #304, #538; identity renewal #36; dead transport handlers #317; `--setuid` #349; FailedPrecondition mapping #665
- **installer** — signed ISO kernel and initrd #354; required build inputs #351
- **luks** — real backend #647; go-luks2 v1.0.0-rc.2 #746; FIPS activation restrictions #26
- **tenant** — tenant VRFs and the platform-services VRF #721 (blocked by #709); owner-invitation route #299
- **gateway** — service layer: VIPs, placement, discovery, identity, policy #722 (blocked by #721); the second gateway #596, then HA state sync #710

## Later

- **volume** — go-blockstore adapter #90; qrdb-backed coordinator #91; volume-mount attestation gate, container volumes, live migration and NFS root #92
- **remote-deploy** — remote agent deploy over QUIC, replacing SSH #54
- **pi-node-roles** — control-plane, compute and gateway templates for raspberrypi: rpi4 first, rpi5 experimental, the 3B+ as standalone compute only if its 1 GB proves enough
- **ha-raft-template** — the three-node control plane that [configs/platform/templates/README.md](configs/platform/templates/README.md) lists as Planned

## Future

- **dht** — trusted DHT for the public peer-to-peer hosting platform; design only, see [docs/dht/](docs/dht/)
- **android-ota** — Android and secure OTA updates; design only, see [docs/firmware/android.md](docs/firmware/android.md)
- **hosted-control-plane** — hosted control plane; not started
- **hsm-device-lifecycle** — provisioning and attestation of HSM devices, the NXP FRDM-IMX95-PRO first #884; the board's Linux image is built by trusted-imx95, not here; not started
- **jetson-orin-node** — NVIDIA Jetson Orin as a robotics compute node, provisioned and attested through UEFI Secure Boot and the firmware TPM, the Raspberry Pi node lifecycle; not started, waits for a borrowed unit

## Dependencies

- **tpm** — [go-quicbaas#1171](../../../go-quicbaas/issues/1171) re-exports in a go-quicbaas release, plus [go-xkms#1442](../../../go-xkms/issues/1442) and [go-xkms#1443](../../../go-xkms/issues/1443) → #720 → #682. [go-quicbaas#1171](../../../go-quicbaas/issues/1171) → **ipxe** #688.
- **pi-node-roles** — a go-qrdb arm64 release → Pi control-plane nodes.
- **daemon** — [go-quicbaas#1150](../../../go-quicbaas/issues/1150) → one authenticated REST and MCP surface #175, #232, #412.
- **gateway** #709 → **tenant** #721 → **gateway** #722 → **daemon** #723 → the v0.2.0-alpha gate #724.
- **gateway** — the second gateway #596 → HA state sync #710.
- **avr-attestation** — consumes trusted-firmware sdk/go v0.3.0-alpha.
- **device-enrollment** — consumes the trusted-firmware xkms adapter by blank import; no version is consumed yet. Registration waits on [trusted-firmware#28](../../../trusted-firmware/issues/28) (phases B and C) and the go-xkms hook tag → #771 → #772. go-xkms verifies the DICE evidence.
