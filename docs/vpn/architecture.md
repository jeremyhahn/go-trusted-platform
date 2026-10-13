# Remote-Access VPN Architecture

> **Status: PARTIAL — the admission core and both data planes (#584 PR 1, PR 2), the gateway service and the operator control plane on every transport with `platformctl vpn` (#584 PR 3) exist, as do the admission wire contract and the client agent core (`pkg/vpn/agent`); the JS SDK client and the web page (#584 PR 4) exist; left for PR 4: `platformctl vpn connect` with its TPM device, factor signers and client data planes.** · Scope: `pkg/sdn/gateway/services/vpn`, `pkg/vpn`, `gatewayd` · Last verified: 2026-10-13
> `pkg/sdn/gateway/services/vpn` ships the lease model, the five-step
> admission pipeline behind `Deps` interfaces, the typed error vocabulary, the
> config schema with its FIPS refusal, the in-memory lease store and the
> `vpn_posture` OPA policy. Everything marked *(planned)* below is still a
> requirement, not a claim. Conflicts between this folder and the code are
> resolved by fixing the code to this contract or amending this contract in
> the same PR — never by silent drift.
> The feature folder is: architecture (this file) · [engineering.md](engineering.md) ·
> [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

## The problem

Administrators reach the platform's control plane today through an interim
firewall VPN that authenticates a key file and nothing else. It knows nothing
about the machine at the other end: whether it booted with Secure Boot, whether
its disk is encrypted, whether its measured state matches what the platform
enrolled, or whether the person holding it proved anything beyond possession of
the key. A stolen laptop with a valid key is an administrator.

The platform already has every ingredient of the right answer — TPM-backed
device identity, remote attestation with golden-measurement verdicts, an OPA
policy engine, hardware-backed multi-factor authentication through the SDK, and
an IPAM allocator — spread across services that never meet at a VPN.

## The shape chosen

A **zero-trust remote-access service** on the gateway with **one admission
control plane and a pluggable data plane**:

```
client agent ──mTLS (IDevID)──▶ vpn-admission (vpn.Service; its own process is planned)
                                   │ 1. identity      calleradmission.Policy.Evaluate
                                   │ 2. attestation   attestation Service.VerifyQuote → verdict.DeviceVerdict
                                   │ 3. posture       opa.OPAEngine.Evaluate("vpn-posture", report)
                                   │ 4. MFA           SDK Security().Auth().{FIDO2,PIV,Factors}()
                                   │ 5. lease         ipam.Allocator.Allocate (TTL)
                                   ▼
                             datapath (planned process) installs the peer
                                   │
                    ┌──────────────┴──────────────┐
             WireGuard peer                  MASQUE CONNECT-IP session
             (kernel, `!fips` builds)        (QUIC/TLS 1.3, every build)
```

An admitted client holds a **lease**, not a standing entitlement: the address,
the peer and the session expire with the lease unless the client re-attests
within it. A verdict that turns from pass to fail, a posture report that drifts,
or an expired lease revokes the peer immediately.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| Keep the interim firewall VPN and add posture checks to it | The firewall authenticates a key; it has no path to the platform's attestation verdicts or device registry. Every check would be a re-implementation of what the platform already owns, in a place that cannot see the TPM. |
| WireGuard only | Its primitives (Curve25519, ChaCha20-Poly1305, BLAKE2s) are not FIPS 140-3 approved, and the portfolio rule is that a feature depending on a non-approved algorithm is compiled out of a FIPS build, not gated at runtime. A regulated deployment would have no remote access at all. |
| IKEv2/IPsec as the FIPS data plane | Approved primitives, but it needs an IKE daemon the platform does not have and cannot own cleanly, and its client story on managed laptops is the OS's, not the platform's. It remains the natural choice for site-to-site tunnels ([docs/gateway/](../gateway/)), not for attested remote access. |
| A TLS VPN of our own design | The IETF already standardised one: MASQUE CONNECT-IP (RFC 9484) over HTTP/3, which runs on the QUIC stack this repository already ships. Designing a private protocol would be exactly the "hand-rolled" surface the security conventions forbid. |
| Admission inside the gatewayd main process | An admission service parses untrusted client input and talks to the TPM verifier, the SDK and OPA; running it beside the routing and firewall programmers with `CAP_NET_ADMIN` is the process model the gateway is moving away from. It runs as its own supervised, unprivileged process and asks the datapath process to install peers. |
| One long-lived credential per client | A standing credential is a stolen-laptop credential. Leases with re-attestation make possession of a key insufficient by construction. |

## Component boundaries

| Piece | Package | Status | Owner / capability row |
|---|---|---|---|
| Operator control plane | `pkg/vpn` — `Service` (peers and posture policies as tenant-scoped records, session status from gateway telemetry, `DesiredVPN` for the desired config); `VPNService` on REST, gRPC, QUIC `0x52`, MCP and Unix; `sdk/go/services/vpn`; `platformctl vpn` | exists (#584 PR 3) | go-trusted-platform — daemon |
| Admission service | `pkg/sdn/gateway/services/vpn` — `Service`, `New`, `Admit`, `Renew`, `Revoke`, `Challenge`, `Sweep`, `Deps`, `Config`, `Lease`, `MemoryLeaseStore` | exists (#584 PR 1); the datapath process client and the admission listener are *(planned)* | go-trusted-platform — "Edge gateway" (docs/00 §R) |
| Device identity | `pkg/attestation/calleradmission` — `Policy`, `New`, `Evaluate`, `PeerFromTLS`, `Decision`, `AttestedPeers`, `Auditor` | exists | go-trusted-platform — attestation |
| Attestation verdict | `pkg/attestation/service` — `Service.VerifyQuote`, `Service.GetQuote`, `Service.CollectHostAttestation`; `pkg/attestation/verdict` — `DeviceVerdict`, `Sink` | exists | go-trusted-platform — attestation |
| Scheduled re-attestation | `pkg/attestation/reporting` — `Collector`, `Cache`, `NewDeviceAddressResolver` | exists | go-trusted-platform — attestation |
| Posture policy | `pkg/policy/opa` — `OPAEngine`, `LoadPolicy`, `Evaluate`, `EvaluationResult`; `pkg/policy/opa/policies/vpn_posture.rego` (package `vpn.posture`, embedded, every violation named by rule) | exists (#584 PR 1) | go-trusted-platform — platform OPA (admission policy) |
| Posture facts on the client | `pkg/uefi` — `ReadSecureBootStatus`, `SecureBootEnabled`; `pkg/ima` — `NewReader`, `NewVerifier`, `Status`; LUKS2 state through the `go-quicbaas/sdk/go/xkms/luks` re-export | collectors exist, report *(planned)* | go-trusted-platform (uefi, ima); go-luks2 via quicbaas (luks) |
| MFA | quicbaas SDK `Security().Auth().FIDO2()` (`FIDO2Client`), `.PIV()` (`XKMSPIVService`), `.Factors()` (`AuthFactorsClient`: `Add`, `List`, `Remove`, `Rotate`, `Relabel`) | exists (see gap below) | go-xkms / go-qrdb via quicbaas |
| Address lease | `pkg/sdn/ipam` — `Allocator.Allocate`, `AllocateSpecific`, `Release`, `ReleaseByDeviceID` | exists | go-trusted-platform — SDN IPAM |
| Peer install | WireGuard via netlink and `golang.zx2c4.com/wireguard/wgctrl`; MASQUE CONNECT-IP sessions in-process on `github.com/quic-go/connect-ip-go` over the repository's quic-go. The `datapath` process that will host them is *(planned, gateway process model #557)* | `pkg/sdn/gateway/services/vpn`, `pkg/sdn/tunnel` | go-trusted-platform — edge gateway |
| Keys at rest | quicbaas SDK `Security().KMS()` (`KMSClient`) | exists | go-xkms via quicbaas |
| Audit | `calleradmission.Auditor` (exists) and the SDK audit surface | exists | go-quicbaas |
| Configuration | `pkg/sdn/gateway/types.go` `ManagementVPNServiceConfig` (`management_vpn`: `enabled` plus the core `vpn.Config`) and `pkg/sdn/config.go` `ManagementVPNConfig` (`Enabled`, `Type`, `AllowTo`) | exist; the `wireguard.*` and `masque.*` keys are *(planned)* | go-trusted-platform |

The SDK edge is the only way down: the service never imports go-xkms, go-qrdb
or go-luks2 directly; `pkg/arch/layerguard_test.go` enforces it and gatewayd's
import closure guard (`pkg/arch/gatewayguard_test.go`) is extended, not
weakened, when the packages above join it.

**Ownership gap to file upstream (docs/00 L8):** the SDK's factor vocabulary
reachable from `Factors()` is `mtls`, `webauthn`/`fido2` and `piv`; a TOTP code
appears only as `MFACode` on the quicbaas auth client's password login. A
one-time-password factor that can be enrolled and verified on its own is not
exposed. Until go-qrdb/go-quicbaas add it, "OTP" in this design means *not
offered*, never a local implementation.

## Data flow — one admission

1. The client agent (`platformctl`, see [cli.md](cli.md)) opens an mTLS
   connection to the admission listener with its **IDevID** certificate.
   `calleradmission.PeerFromTLS` extracts the peer; `Policy.Evaluate` returns a
   `Decision`. A refused decision ends the flow with the reason class recorded
   by the `Auditor`; there is no operator fallback on this listener.
2. The admission service issues a nonce; the agent answers with a TPM quote
   and its host attestation (`manifest.HostAttestation`: PCRs, AK public key,
   IDevID certificate). `attestation/service.Service.VerifyQuote` produces the
   `verdict.DeviceVerdict` against the device's enrolled profile; `Passed` and
   `Cryptographic` must both be true.
3. The agent sends its **posture report** (the facts in
   [engineering.md](engineering.md) §Posture). The report is the OPA input;
   `OPAEngine.Evaluate` on the tenant's `vpn_posture` policy returns
   `EvaluationResult`; any `Violation` refuses.
4. The **person** proves presence: a FIDO2 assertion (`FIDO2Client`) or a PIV
   signature (`XKMSPIVService`) bound to the session nonce, against the factors
   enrolled for the operator (`AuthFactorsClient.List`). Device identity is not
   a second factor for the person; the person's factor is required on every
   fresh session, and again on lease renewal if the tenant policy says so.
5. The service allocates an address from the tenant's remote-access pool
   (`Allocator.Allocate` with the device id as owner) and asks the data plane
   to install the peer. WireGuard programs a kernel peer whose only allowed
   address is the leased one; MASQUE binds that address to the fingerprint of
   the client certificate this admission ran under, and the CONNECT-IP session
   presenting that certificate is assigned it. The response to the agent
   carries the address, the gateway endpoint, and — per data plane — the
   WireGuard server public key or the MASQUE URI template.
6. The `reporting.Collector` schedules re-attestation of the device inside the
   lease; a failed verdict, a violated posture or an expired lease releases the
   address (`Allocator.Release`) and removes the peer. Every transition is an
   audit record.

What crosses a boundary: the mTLS session and the data-plane session cross the
internet; the admission → datapath request crosses a process boundary on the
gateway (gRPC over a Unix socket in the planned process model); the verdict,
posture policy and factors are read from the control plane through the SDK.
Nothing about the client is persisted on the gateway beyond the lease table;
leases and posture policies are tenant-scoped entities on the control plane.

## Trust boundaries

1. **Internet → admission listener.** Everything arriving is untrusted. The
   listener speaks mTLS only; a connection without a client certificate chained
   to the platform anchors is closed before any application byte is parsed.
2. **Admission → TPM verifier and OPA.** Both fail closed: a verifier that
   cannot evaluate a quote is a refusal, an OPA policy that cannot be loaded is
   a refusal (`ErrPolicyNotFound`, `ErrEvaluationFailed` are refusals, never
   "no policy means allow").
3. **Admission → datapath.** The admission process holds no `CAP_NET_ADMIN`; it
   may only ask for a peer with a lease and may only revoke peers it created.
4. **Data plane → platform networks.** An admitted client reaches only the
   zones its lease names (`ManagementVPNConfig.AllowTo`), enforced by the
   gateway's zone matrix — the same compiled matrix that programs the OVS flows
   and the trusted proxy — not by a separate VPN ACL.
5. **Keys.** The WireGuard server private key and the MASQUE listener's TLS
   identity are issued and stored through the SDK KMS; the WireGuard key is
   handed to the kernel at start and never written to disk in the clear.
6. **FIPS.** Under the `fips` build tag the WireGuard data plane does not
   exist — not disabled, absent — and only MASQUE is offered. A configuration
   selecting WireGuard in a FIPS build is refused at config load.

## What this feature deliberately does not do

- **It is not a site-to-site tunnel.** Gateway-to-gateway and gateway-to-relay
  transport (GRE, IPsec) is the edge gateway's tunnel service
  ([docs/gateway/](../gateway/)).
- **It does not authorise by network position.** A client on the office LAN is
  admitted by the same five steps as one on hotel Wi-Fi.
- **It does not run an authorization engine for tokens.** Who may reach which
  zone is the zone matrix; the person's role governs which leases they may
  request, through the SDK's IAM, not a VPN-local table.
- **It does not implement OTP.** See the ownership gap above.
- **It does not replace the interim firewall VPN until proven.** Cutover is a
  deployment decision made after this feature has carried administrative
  traffic for a defined burn-in; the interim endpoint stays as rollback.
