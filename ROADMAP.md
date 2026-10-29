# go-trusted-platform roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-16
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
- **installer** — a booting node authenticates to the control-plane API with its IDevID over mTLS, the install-completion webhook included — [#238](../../issues/238) — open

## Next
- **bootstrap** — every NBD package behind one build tag, omitted from a client binary that does not use NBD — [#883](../../issues/883) — open
- **installer** — the initrd brings up the WireGuard overlay and attaches the NBD root inside it — [#883](../../issues/883) — open
- **attestation** — the SDK peer verifier replaces the VM verifier and the DevID validator — [#666](../../issues/666) — open
- **auth** — users held in go-quicbaas IAM, no user store of the platform's own; ruling 133: the daemon REST plane authenticates and authorises only through the go-quicbaas SDK (IAM, JWT, WebAuthn, PIV, mTLS, RBAC/ABAC), with no auth model, route guard or token format of its own — [#644](../../issues/644) — open
- **bootstrap** — the FIPS Noise bootstrap listener — [#518](../../issues/518) — open
- **daemon** — MCP refuses anonymous enumeration and every tool has a permission — [#412](../../issues/412) — open
- **installer** — root seal on `luks-root` and offline unseal from the `.tpmpolicy` binding record — [#720](../../issues/720) — blocked: waits on the go-quicbaas tag that carries go-xkms#1443 step 3
- **luks** — the LUKS service on a real backend — [#647](../../issues/647) — open
- **policy-engines** — `pkg/sdn/policy` folded into one of the two engines (access → go-qrdb ABAC through the SDK, evidence → OPA) — [docs/sdn/](docs/sdn/) — open
- **policy-engines** — Rego policies held in the datastore and served through the go-quicbaas SDK, with the embedded set as the floor; ruled option A: go-qrdb ABAC answers every access question, OPA every evidence question including image admission and workload compliance — [docs/security/](docs/security/) — open
- **policy-engines** — OPA behind one build tag, so a binary that evaluates no evidence omits it (as the NBD build tag) — [docs/security/](docs/security/) — open
- **tenant** — tenant VRFs and the platform-services VRF — [#721](../../issues/721) — blocked: waits on #709
- **bootstrap** — the seed model with control-plane, gateway and compute templates, the EK policy and EK retrieval through the BMC or the device — [#883](../../issues/883) — open
- **device-enrollment** — enrollment from pre-defined device configurations through enroll-01 and endorse-01, continuously attested — [#883](../../issues/883) — open

## Later
- **gateway-supervisor** — the gateway services as one process each under platformd, the zebra-role route owner and BGP graceful restart (ruling 240 item 4) — [#1191](../../issues/1191) — open
- **volume** — go-blockstore volumes on go-qrdb's volume pools, with the trust and workload wiring — [#90](../../issues/90) — open
- **remote-deploy** — remote agent deploy over QUIC, replacing SSH — [#54](../../issues/54) — open
- **pi-node-roles** — control-plane, compute and gateway templates for raspberrypi — [Raspberry Pi templates](configs/platform/templates/dedicated/raspberrypi/README.md) — open
- **ha-raft-template** — the three-node control plane — [configs/platform/templates/README.md](configs/platform/templates/README.md) — open
- **sev-snp** — SEV-SNP guest attestation reports appraised as RFC 9334 Evidence, the report and AMD chain verified by go-xkms through the go-quicbaas SDK; not started — [SPEC Features](docs/SPEC.md#features) — blocked: waits for the HPE DL380 Gen10 Plus v2 to arrive
- **sev-snp** — SEV-SNP guests on the compute QEMU/KVM provider, with the guest's vTPM bound to its SNP report; not started — [SPEC Features](docs/SPEC.md#features) — blocked: waits for the HPE DL380 Gen10 Plus v2 to arrive
- **sev-snp** — the DL380 as the CI runner for the SEV-SNP suites; not started — [SPEC Features](docs/SPEC.md#features) — blocked: waits for the HPE DL380 Gen10 Plus v2 to arrive
- **dns** — `platformctl` has no `dns` command group: DNS is reached through the daemon's REST, gRPC, QUIC, MCP and Unix APIs ([docs/dns/api.md](docs/dns/api.md)), and the SPEC dns row names no CLI group, so this is a recorded omission, not scope — [#954](../../issues/954) — open

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
- Standards watch: draft-ietf-rats-corim-11, pinned at revision -11, implemented in `pkg/attestation/`; a new revision or its RFC updates [docs/reference/rats/](docs/reference/rats/) and the code.
- Standards watch: draft-ietf-lamps-csr-attestation-30, pinned at revision -30, implemented in `pkg/attestation/` and the enrollment paths (`pkg/device/`, `pkg/webservice/v1/device/`, `pkg/api/daemon/`, `pkg/installer/`, `pkg/firstboot/`); a new revision or its RFC updates [docs/reference/rats/](docs/reference/rats/) and the code.
- Downstream: the go-recountly deployment, the automatethethings.com launch and the P1 staging run wait on Dev complete.
