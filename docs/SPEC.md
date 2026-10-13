# go-trusted-platform specification

> **Status: NORMATIVE** · Scope: the whole repository
> Conflicts with this document are defects. Fix them here first.
> [ROADMAP.md](../ROADMAP.md) orders the work this file specifies; the two agree feature for feature.

A feature listed in this file, in any status, is never deleted: not its docs, code or issues. Removing or re-scoping a feature needs the owner's change to this file.

## 1. Purpose

go-trusted-platform is a Trusted Computing software platform: the trusted-computing platform product and control plane for provisioning, node and workload attestation (Attester and Relying Party), SDN, the `gatewayd` edge gateway, the attestation-gated OCI registry, DNS, tenancy and fleet operations.
It is the top of the four-layer stack (go-qrdb, go-xkms, go-quicbaas, go-trusted-platform): it imports only the go-quicbaas SDK, including its `sdk/go/xkms/*` re-exports, and re-exports the composed stack.
Its consumers are OEM device manufacturers, enterprise administrators, platform administrators and end users; it may be used as a program, toolkit or library for building platforms and services on trusted and confidential computing.

## 2. Boundaries

The platform owns:

- the platform services: TPM bring-up, IDevID, attestation, SDN, DNS, BMC, ISO, initrd orchestration, the installer and the daemon;
- its own keystores, CA, LUKS sealer and signing backends, constructed through the `sdk/go/xkms/*` re-exports for its own product surfaces;
- the exposure of every service on REST, gRPC, QUIC, MCP and the Unix socket, with feature parity across them.

The platform never:

- imports `go-xkms/pkg/*`, `go-xkms/sdk/go/*`, `go-qrdb`, `go-quicraft` or `go-truststrap`; the one upstream path is the `go-quicbaas/sdk/go` re-export;
- re-implements a go-quicbaas surface or anything the SDK exposes (FIDO2, WebAuthn, barrier, ceremony, trust-bootstrap dispatch, TPM sealing); a missing capability means the SDK is extended, not bypassed;
- composes go-xkms implementations into go-qrdb seams (`StrategyRegistry`, `PINBackend`, `FactorRegistry`, `CeremonyCA`); that composition is go-quicbaas's alone;
- ships a "wire this up later" stub on a transport (`NotImplementedError`, `BaasTransportNotSupportedError`, `not yet supported by SDK`);
- builds the P2P network beyond design.

## 3. Features

Status is exactly one of `shipped`, `in progress`, `planned`, `future`. A feature folder `docs/<feature>/` is the requirements contract behind its row.

| feature | status | requirements | detail |
|---|---|---|---|
| attestation | in progress | Verify a three-level chain in order: the host (rooted in the physical TPM), the VM (its own virtual TPM) and the container (a platform PCR), each bound to an attested host; serve the verified report with its verdict and age. See [architecture](attestation/architecture.md). | [docs/attestation/](attestation/) |
| auth | in progress | Turn a certificate (a TPM-issued IDevID, an enrollment credential, a platform-issued client certificate) into one identity, and let human and service principals authenticate with mTLS, FIDO2 or PIV, so downstream authorization has one input. See [architecture](auth/architecture.md). | [docs/auth/](auth/) |
| barrier | shipped | Keep data at rest unreadable behind one encryption layer with an init, unseal, seal lifecycle; reach the key hierarchy, seal strategies, Shamir splitting and ceremony through the SDK; bind no production transport until the barrier is unsealed. See [architecture](barrier/architecture.md). | [docs/barrier/](barrier/) |
| bmc | shipped | Control a machine out of band (power, boot device, virtual media, sensors, inventory, serial console, MAC discovery) over IPMI and Redfish, and make the BMC trustworthy: replace and pin its certificate, publish DANE records, protect and rotate its credentials. See [architecture](bmc/architecture.md). | [docs/bmc/](bmc/) |
| bootstrap | in progress | Make a machine the platform has never seen into one it trusts: break the trust-before-trust loop for the CA bundle, and give identity to a machine that has no operating system. See [architecture](bootstrap/architecture.md). | [docs/bootstrap/](bootstrap/) |
| ca | shipped | Host the stack's CA and ACME through the SDK, and issue certificates for nodes, devices, workloads, service endpoints and agents automatically, authorised by neither a human nor a shared secret. See [architecture](ca/architecture.md). | [docs/ca/](ca/) |
| cluster | shipped | Expose this repository's half of clustering; never implement consensus, peer discovery or cluster formation, which are owned below. See [architecture](cluster/architecture.md). | [docs/cluster/](cluster/) |
| compute | shipped | Run workloads through one orchestrator over QEMU/KVM, podman and optionally AWS, Azure or GCP, enforcing that a workload is proved to be what it claims and is allowed on its network by something other than its own assertion. See [architecture](compute/architecture.md). | [docs/compute/](compute/) |
| daemon | in progress | Serve one daemon on six transports over shared services, so a shell user, an in-process Go program, the desktop GUI, a network service, a booting machine and an AI agent get the same answer; roles are configuration across six binaries. See [architecture](daemon/architecture.md). | [docs/daemon/](daemon/) |
| device | shipped | Keep the profile, the pre-boot record of what a machine gets and may reach, and the device, the post-enrollment record of what showed up with its TPM keys and lifecycle state, and check that the one is the machine the other was written for. See [architecture](device/architecture.md). | [docs/device/](device/) |
| dht | future | Trusted DHT for the public peer-to-peer hosting platform on trusted-platform devices. Design only; no code exists. See [architecture](dht/architecture.md). | [docs/dht/](dht/) |
| dns | shipped | Serve authoritative DNS inside the platform with CoreDNS as the engine and a generated Corefile; sign the names with DNSSEC; publish records on demand for DANE and ACME DNS-01. See [architecture](dns/architecture.md). | [docs/dns/](dns/) |
| eab | shipped | Prove a machine being installed was expected, with ACME External Account Binding (RFC 8555 §7.3.4) key pairs issued and tracked by the platform, before it receives configuration or a Secure Boot DB signature. See [architecture](eab/architecture.md). | [docs/eab/](eab/) |
| factory-image | in progress | Produce a complete, encrypted, signed-boot platform install on a card for devices that cannot boot an ISO, such as a Raspberry Pi, which becomes a provisioned node on its first boot. See [architecture](factory-image/architecture.md). | [docs/factory-image/](factory-image/) |
| firmware | in progress | Make firmware refuse anything the platform did not authorise without bricking the machine: Secure Boot enrollment, UKI and Authenticode signing; attest trusted-firmware AVR devices through the AVR provider. See [architecture](firmware/architecture.md). | [docs/firmware/](firmware/) |
| gateway | in progress | Terminate untrusted traffic in a separate binary, `gatewayd`, whose capabilities are independently enabled service sections: overlay, edge, transit, BGP, firewall, DHCP, PXE, load balancer, NAT, tunnels, the trusted reverse proxy and the host packet filter. See [architecture](gateway/architecture.md). | [docs/gateway/](gateway/) |
| health | shipped | Report which `platformd` subsystem is degraded; never answer healthy with an expired CA certificate, and never let one hung probe block the endpoint. See [architecture](health/architecture.md). | [docs/health/](health/) |
| iam | shipped | Answer "who is this" the same way for humans, service accounts, agents, devices and workloads by re-exporting the stack's IAM, OIDC and single RBAC decision point; implement none of it. See [architecture](iam/architecture.md). | [docs/iam/](iam/) |
| ima | shipped | Provision Linux IMA on installed nodes so files are measured on access into an append-only log extended into PCR 10, closing the gap Secure Boot leaves after the kernel starts. See [architecture](ima/architecture.md). | [docs/ima/](ima/) |
| installer | in progress | Bring a node to a state where it boots only software the platform signed and releases its disk key only to a boot chain measured as the platform expects, across the installer and the first production boot. See [architecture](installer/architecture.md). | [docs/installer/](installer/) |
| ipxe | in progress | Decide, at network boot, what an unprovisioned machine runs as its first executable, handing legacy-BIOS and UEFI PXE ROMs the binary each needs. The provisioning-zone rules admit TCP 8080, 8081 and 10809. See [architecture](ipxe/architecture.md). | [docs/ipxe/](ipxe/) |
| kms | shipped | Give every layer its keys (CA signing keys, per-tenant and per-image DEKs, node identities, sealed secrets) wherever a deployment lets them live: TPM, PKCS#11 HSM, cloud KMS or software, by re-exporting the stack's key management. See [architecture](kms/architecture.md). | [docs/kms/](kms/) |
| luks | in progress | Expose LUKS2 key-slot operations on a provisioned host (add a passphrase, bind FIDO2 or the TPM, cut a recovery key, retire a slot, rotate a passphrase) as one platformd service on every transport, under the platform's authorization and FIPS keyslot policy. See [architecture](luks/architecture.md). | [docs/luks/](luks/) |
| ntp | shipped | Keep node time trustworthy, since TPM attestation freshness, ACME issuance windows and DANE/DNSSEC signature windows are silently wrong on a wrong clock. See [architecture](ntp/architecture.md). | [docs/ntp/](ntp/) |
| provisioning | shipped | Turn a racked, powered-on bare machine into a trusted platform node without anyone logging into it and without trusting anything the machine says about itself. See [architecture](provisioning/architecture.md). | [docs/provisioning/](provisioning/) |
| proxy | shipped | Front applications that cannot attest with a reverse proxy whose authentication is an injected chain of platform-native mechanisms, aware of the caller's TPM, network zone and attestation freshness. See [architecture](proxy/architecture.md). | [docs/proxy/](proxy/) |
| registry | shipped | Serve an OCI registry whose authentication is TPM attestation, verifying the quote's signature, freshness and PCRs. See [architecture](registry/architecture.md). | [docs/registry/](registry/) |
| sdk | in progress | Ship `sdk/go`, the separate Go module that is the only way `platformctl` reaches the daemon, carrying every `platform.v1` service over six transports with the same client types on each. See [architecture](sdk/architecture.md). | [docs/sdk/](sdk/) |
| sdn | shipped | Make the switch port the enforcement point: validate the IDevID a device presents, decide its zone and program OpenFlow to match; until then the port is provisioning-only or quarantined. See [architecture](sdn/architecture.md). | [docs/sdn/](sdn/) |
| secrets | shipped | Let a configuration value be a secret URI, resolved in place before any service reads it, so no credential has to live in the configuration file. See [architecture](secrets/architecture.md). | [docs/secrets/](secrets/) |
| security | shipped | Hold the platform's local security machinery: rate limiters, input validators and sanitizers, and the embedded OPA engine with its built-in Rego policies. See [architecture](security/architecture.md). | [docs/security/](security/) |
| switch | shipped | Drive physical switch ports between the restricted and production networks over SSH, a security-critical transition that holds an administrator credential on the network fabric. See [architecture](switch/architecture.md). | [docs/switch/](switch/) |
| tenant | in progress | Isolate tenants as independent allocations plus a quota, each enforced by a different layer: the keyspace in the store key, a DEK for encryption at rest, the quota at admission. See [architecture](tenant/architecture.md). | [docs/tenant/](tenant/) |
| tpm | shipped | Drive a TPM 2.0 the platform does not own consistently across six transports, never letting a caller silently get a weaker root of trust than it asked for. See [architecture](tpm/architecture.md). | [docs/tpm/](tpm/) |
| trust | shipped | Hold the platform anchor, the unconfigurable platform CA, and resolve peers the platform did not issue through the ordered strategy chains of `trust.bootstrap` and `trust.bmc`. See [architecture](trust/architecture.md). | [docs/trust/](trust/) |
| vpn | in progress | Admit remote administrators through one control plane (device identity, attestation verdict, posture, MFA, an IPAM lease) onto WireGuard (non-FIPS builds) or MASQUE CONNECT-IP. See [architecture](vpn/architecture.md). | [docs/vpn/](vpn/) |
| vtpm | shipped | Give each attestable VM one swtpm instance, packaged as a bundle with its own state, NVRAM, control socket and a CA-issued EK certificate. See [architecture](vtpm/architecture.md). | [docs/vtpm/](vtpm/) |
| web | shipped | Serve the control panel as a statically exported application from the platform's own HTTP server, optionally compiled into the binary, with no separate UI service and no server-side runtime. See [architecture](web/architecture.md). | [docs/web/](web/) |
| avr-attestation | shipped | Attest trusted-firmware AVR devices through the AVR attestation provider. Provider only: it consumes trusted-firmware `sdk/go` v0.3.0-alpha. | [docs/firmware/avr-attestation.md](firmware/avr-attestation.md) |
| sdk-javascript | shipped | Provide the TypeScript SDK (`trusted-platform-sdk`, `sdk/javascript`) for web applications; the control panel consumes the platform through it. | none |
| device-enrollment | in progress | Own AVR device enrollment, the device registry and fleet policy. Use trusted-firmware `sdk/go` directly and reach the AVR backend by blank-importing the trusted-firmware `xkms` adapter. go-xkms verifies the DICE evidence. The HAL-ported MCU boards from trusted-firmware (RP2350, ESP32-C6, nRF54L15, STM32H5) enroll as device classes. | none |
| volume | planned | Add a go-blockstore volume adapter and configuration, a qrdb-backed coordinator, and the trust and workload wiring: a volume-mount attestation gate, container volumes, live migration and NFS root. | none |
| remote-deploy | planned | Deploy the remote agent over QUIC, replacing SSH, FIPS-native. | none |
| pi-node-roles | planned | Provide control-plane, compute and gateway templates for raspberrypi: rpi4 first, rpi5 experimental, the 3B+ as standalone compute only if its 1 GB proves enough. Pi control-plane nodes depend on a go-qrdb arm64 release. | none |
| ha-raft-template | planned | Provide the three-node control plane that [configs/platform/templates/README.md](../configs/platform/templates/README.md) lists as Planned. | none |
| hsm-device-lifecycle | future | Provision, enroll and attest HSM devices and run the zero-trust operations for them, the NXP FRDM-IMX95-PRO first; the board runs go-xkms as a dedicated HSM appliance. The platform builds no device firmware. Open question for the owner: does the board's Linux image come from this repository's image pipeline or from the trusted-imx95 repository? Not started. | none |
| jetson-orin-node | future | Provision and attest the NVIDIA Jetson Orin as a robotics compute node through the UEFI Secure Boot and firmware TPM path, with the same node lifecycle as the Raspberry Pi. Nothing is done before a borrowed unit arrives. Not started. | none |
| android-ota | future | Support Android, GrapheneOS first, with secure OTA updates. Design only. | [docs/firmware/android.md](firmware/android.md) |
| hosted-control-plane | future | Offer a managed control plane (hosted CA, IAM, KMS and DNS) with a flexible data-plane deployment. Not started. | none |

## 4. Interfaces

- SDK: Go, `sdk/go`, [docs/sdk/architecture.md](sdk/architecture.md); JavaScript, `trusted-platform-sdk`, [docs/api/sdk-javascript.md](api/sdk-javascript.md).
- CLI and binaries: `platformd`, `platformctl` (CLI and desktop GUI), `pxeboot`, `platform-initrd`, `deployer-pin`, [docs/daemon/cli.md](daemon/cli.md); `gatewayd`, [docs/gateway/cli.md](gateway/cli.md).
- API transports: Embedded, Unix, gRPC, REST, QUIC, MCP, [docs/daemon/api.md](daemon/api.md) (canonical).
- Web UI: the control panel served by `platformd`, [docs/web/architecture.md](web/architecture.md).

## 5. Release criteria

The "Release candidate" milestone closes when all of the following are true.

The stack and the release:

- The platform is on the go-quicbaas and go-xkms v0.2.0 upstream tags (#720).
- v0.2.0-alpha passes E2E, benchmarks and hardware acceptance and is tagged (#724); public-release readiness is met (#703).
- Every test package runs in a CI stage (#34).
- `docs/` passes the spec-review scrub and banner conformance, and the hardware validation runbook and docs are consolidated (#833, #756, #692).

Each in-progress feature is complete:

- attestation: go-xkms's canonical peer verifier replaces the VM verifier and the DevID validator, and the device quote verifier uses the upstream attested-peer primitive (#666, #482); an attestation status source feeds go-qrdb admission (#715); multi-protocol parity and production wiring of every attestation operation (#545, #498, #386).
- auth: one user store on go-quicbaas IAM (#644); a registered account can log in, logout ends the session server-side, mTLS sign-in works, a browser login's session names the one tenant #662 settles, and its owner flag matches that tenant (#640, #213, #199, #662); admin CSR, PIV and FIDO2 enrollment verified on hardware (#281).
- bootstrap: the FIPS Noise bootstrap listener accepts the approved P-256 suite (#518); the seeder authenticates as `admin@system` over mTLS (#176).
- daemon: ops, namely backup/restore, hitless upgrades, metrics/SLOs, troubleshooting, audit and switch render (#723); identity certificates renew (#36); one authenticated REST surface (#232, #175); MCP refuses anonymous enumeration and every tool has a permission (#412, #304, #538); a transport handler that exists is the one that runs (#317); `--setuid` works (#349); the FailedPrecondition mapping is decided (#665).
- device-enrollment: AVR enrollment, the device registry and the gateway relay (#696), and a DICE AVR enrolled end to end (#772).
- factory-image: the Raspberry Pi factory image epic closes (#667).
- firmware: AVR support on trusted-firmware (#771).
- gateway: the network edge replaces the edge routers (#553): the EVPN/VXLAN overlay service (#709), the service layer (#722), the process model (#557, #657), gateway ops (#65), load-balancer, perf and NAT64 surfaces wired (#660), secret-store identity and scheme (#658, #659), the second gateway (#596) and HA state sync (#710).
- installer: the ISO kernel and initrd are signed (#354); every required build input is enforced (#351).
- ipxe: Raspberry Pi network boot and bootstrap on real hardware (#685): per-node platform, model, architecture, serial and boot model in `bootstrap.yaml` (#688), diskless NBD-over-TLS with IDevID client authentication (#689), the first stage verified on hardware (OTP burn, EEPROM acceptance) and the hardware runbook (#692); the install-completion webhook authenticates its caller (#238).
- luks: the service has a real backend (#647) on go-luks2 v1.0.0-rc.2 (#746); FIPS activation restrictions hold (#26).
- sdk: the full composed go-quicbaas surface is re-exported (#704) and every SDK route matches its server route (#452).
- tenant: tenant VRFs and the platform-services VRF (#721); the system admin can call the owner-invitation path (#299).
- vpn: the attested remote-access VPN (#584).

Each shipped feature has no open release defect:

- bmc: no ungated BMC router (#237).
- ca: ACME issues a node certificate from the control plane (#431).
- cluster: the cluster gRPC and MCP surfaces are not stubs (#334).
- device: no unauthenticated device-config disclosure (#177); restricted IDevID keys serve device mTLS (#149); no stubbed profile assignment in the adapters (#488).
- dns: a persisted zone picks up configuration changes (#220).
- provisioning: E2E provisioning Phases 2 and 3 assert what they report (#372).
- sdk-javascript: attest response types and test assertions match the declared types (#499, #246).
- sdn: the SDN integration suite is green on main (#730).
- secrets: provisioning and secret materialization conform to protected memory (#60).
- tpm: the TPM multi-protocol suite is green on every transport and in CI (#682); IDevID and IAK are re-keyed to the TCG Template H-0 policy (#581).
- web: device registration, the profile hostname and the SDN/DNS wire shape agree with the API (#455, #413, #445).
