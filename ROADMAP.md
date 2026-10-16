# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-15
> The one roadmap of this repository. [docs/SPEC.md](docs/SPEC.md) specifies the features; this file orders them and names each by its SPEC table name. The issue tracker is the backlog. Older plans are in `docs/archive/`.

## Mission
The trusted-computing platform product and control plane: provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, the attestation-gated OCI registry, DNS, tenancy and fleet ops. Layer 5 of the stack: it embeds go-quicbaas as a library and re-exports through `sdk/go` every go-quicbaas service, with the go-qrdb database and go-xkms hardware crypto services beneath it, adding its platform services on top.

## Milestones
- [Dev complete](../../milestone/16) — RC — due 2026-11-23 — 77 open / 107 closed

## Complete
- **barrier** — data at rest behind one encryption layer with init, unseal and seal — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **bmc** — out-of-band control over IPMI and Redfish with a pinned BMC certificate — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **ca** — the stack's CA and ACME, re-exported through the go-quicbaas SDK — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **cluster** — the deployment's one go-qrdb cluster, re-exported through `sdk/go` — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **compute** — one workload orchestrator over QEMU/KVM, podman and cloud providers — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **device** — profiles and enrolled devices, checked against each other — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **dns** — authoritative DNS on CoreDNS, signed with DNSSEC — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **eab** — ACME External Account Binding for expected machines — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **health** — per-subsystem health that no hung probe blocks — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **iam** — the stack's IAM, OIDC and RBAC, re-exported — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **ima** — Linux IMA provisioned on installed nodes — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **kms** — keys on TPM, PKCS#11, cloud KMS or software through the stack's key management — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **ntp** — trustworthy node time — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **provisioning** — a bare machine becomes a trusted node with no login — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **proxy** — an attestation-aware reverse proxy — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **registry** — an OCI registry authenticated by TPM attestation — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **sdn** — the switch port enforces the zone the device's IDevID decides — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **secrets** — secret URIs resolved in configuration — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **security** — rate limiters, input validators and the embedded OPA engine — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **switch** — switch ports moved between restricted and production networks over SSH — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **tpm** — one TPM 2.0 surface on six transports — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **trust** — the platform anchor and the `trust.bootstrap` and `trust.bmc` resolver — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **vtpm** — one swtpm instance per attestable VM — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **web** — the control panel served by `platformd` — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done
- **avr-attestation** — the AVR attestation provider — [PR #700](../../pulls/700) — done
- **sdk-javascript** — the TypeScript SDK for web applications — [v0.1.0-alpha](../../releases/tag/v0.1.0-alpha) — done

## Now
- **ipxe** — Raspberry Pi network boot and bootstrap on real hardware — [#685](../../issues/685) — open
- **gateway** — the network edge replaces the edge routers — [#553](../../issues/553) — open
- **factory-image** — the Raspberry Pi factory image — [#667](../../issues/667) — open
- **firmware** — AVR support on trusted-firmware — [#771](../../issues/771) — open
- **device-enrollment** — AVR enrollment, device registry and gateway relay — [#696](../../issues/696) — open
- **sdk** — the full composed go-quicbaas surface re-exported — [#704](../../issues/704) — open
- **vpn** — the attested remote-access VPN: multi-protocol surface, CLI and client agent — [#584](../../issues/584) — open

## Next
- **attestation** — the SDK peer verifier replaces the VM verifier and the DevID validator — [#666](../../issues/666) — open
- **auth** — users held in go-quicbaas IAM, no user store of the platform's own — [#644](../../issues/644) — open
- **bootstrap** — the FIPS Noise bootstrap listener — [#518](../../issues/518) — open
- **daemon** — MCP refuses anonymous enumeration and every tool has a permission — [#412](../../issues/412) — open
- **installer** — root seal on `luks-root` and offline unseal from the `.tpmpolicy` binding record — [#720](../../issues/720) — blocked: waits on the go-quicbaas tag that carries go-xkms#1443 step 3
- **luks** — the LUKS service on a real backend — [#647](../../issues/647) — open
- **sdn** — `pkg/sdn/policy` folded into one of the two engines (access → go-qrdb ABAC through the SDK, evidence → OPA) — [docs/sdn/](docs/sdn/) — open
- **security** — Rego policies held in the datastore and served through the go-quicbaas SDK, with the embedded set as the floor; ruled option A: go-qrdb ABAC answers every access question, OPA every evidence question including image admission and workload compliance — [docs/security/](docs/security/) — open
- **security** — OPA behind one build tag, so a binary that evaluates no evidence omits it (as the NBD build tag) — [docs/security/](docs/security/) — open
- **tenant** — tenant VRFs and the platform-services VRF — [#721](../../issues/721) — blocked: waits on #709

## Later
- **volume** — go-blockstore volumes on go-qrdb's volume pools, with the trust and workload wiring — [#90](../../issues/90) — open
- **remote-deploy** — remote agent deploy over QUIC, replacing SSH — [#54](../../issues/54) — open
- **pi-node-roles** — control-plane, compute and gateway templates for raspberrypi — [Raspberry Pi templates](configs/platform/templates/dedicated/raspberrypi/README.md) — open
- **ha-raft-template** — the three-node control plane — [configs/platform/templates/README.md](configs/platform/templates/README.md) — open
- **standards-watch** — draft-ietf-rats-corim-11 pinned; a new revision or its RFC updates `docs/reference/rats/` and the code — [docs/reference/rats/](docs/reference/rats/) — pinned -11
- **standards-watch** — draft-ietf-lamps-csr-attestation-29 pinned; a new revision or its RFC updates `docs/reference/rats/` and the code — [docs/reference/rats/](docs/reference/rats/) — pinned -29

## Future
- **dht** — trusted DHT for the public peer-to-peer hosting platform; design only — [docs/dht/](docs/dht/) — open
- **android-ota** — Android and secure OTA updates; design only — [docs/firmware/android.md](docs/firmware/android.md) — open
- **hosted-control-plane** — hosted control plane; not started — [SPEC Features](docs/SPEC.md#features) — open
- **hsm-device-lifecycle** — provisioning and attestation of HSM devices, the NXP FRDM-IMX95-PRO first; not started — [#884](../../issues/884) — open
- **jetson-orin-node** — the NVIDIA Jetson Orin as a robotics compute node; not started — [SPEC Features](docs/SPEC.md#features) — blocked: waits for a borrowed unit

## Dependencies
- Upstream go-quicbaas: pinned v0.12.0-alpha; needed the tag that carries [go-xkms#1443](../../../go-xkms/issues/1443) step 3, [go-xkms#1442](../../../go-xkms/issues/1442) and the [go-quicbaas#1171](../../../go-quicbaas/issues/1171) re-exports (#720, #682, #688), [go-quicbaas#1150](../../../go-quicbaas/issues/1150) (#175, #232, #412), and the release that composes trusted-firmware's `xkms` adapter after [trusted-firmware#28](../../../trusted-firmware/issues/28) phases B and C (#771, #772).
- Upstream go-qrdb: an arm64 release, reached through go-quicbaas, for Pi control-plane nodes.
- Upstream go-luks2: pinned v0.2.0-alpha; needed v1.0.0-rc.2 (#746).
- Downstream: the go-recountly deployment, the automatethethings.com launch and the P1 staging run wait on Dev complete.
