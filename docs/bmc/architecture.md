# BMC — Architecture

> **Status: NORMATIVE** · Scope: `pkg/bmc/`, `pkg/quirks/`, `pkg/bmc/smc/`, `pkg/bmc/credentials/`, `pkg/bmc/attestation/` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Verification scope.** Every package, type, constant, route, opcode and flag
> below was read out of the tree on 2026-08-18. The legacy files this folder held
> (`README.md`, `configuration.md`, `operations.md`, `sdk.md`, `testing.md`) are
> deleted; these five files hold their content. Where they disagreed with the
> code, the correction is stated in §9.

---

## 1. The problem

A bare-metal node has no operating system until the platform puts one there,
and no identity until the platform issues one. Everything the platform needs to
do *before* first boot — power it on, point it at an installer, watch the
serial console, learn its MAC address — has to happen through the one processor
that is already running: the baseboard management controller.

That processor is also the weakest link in the trust chain. It ships with a
vendor default password, a self-signed certificate nobody vouched for, and full
control over the host. Treating it as "just another HTTP endpoint" means the
platform's root of trust is gated by a credential printed on a sticker.

So this feature has two jobs that are usually written as one:

1. **Control the machine out of band** — power, boot device, virtual media,
   sensors, inventory, serial console, MAC discovery.
2. **Make the BMC itself trustworthy** — capture its factory identity, replace
   it with a platform-issued certificate, pin it, publish DANE records for it,
   store its credentials in protected memory, and rotate them.

## 2. The shape chosen

**One protocol-agnostic `Client` interface, two transports behind it, and a
data-driven quirk registry that keeps every vendor name out of the control
paths.**

- `bmc.Client` (`pkg/bmc/types.go`) is the whole out-of-band control surface:
  power, boot device, virtual media, sensors, system info, SOL console, UEFI
  boot-entry clear, close. Both `ipmiClient` and `redfishClient` implement it.
- `bmc.Service` (`pkg/bmc/service.go`) is the profile-facing layer: it resolves
  a device profile ID to a `*bmc.Config` through a `ProfileStore`, builds a
  client through a `ClientFactory`, and caches it in a `sync.Map` keyed by
  profile ID.
- **Vendor deviations are data, never branches.** `pkg/quirks` holds the only
  table in the codebase permitted to contain manufacturer and model strings
  (`registry.go` says so in its own doc comment). Callers invoke
  `quirks.ResolveIdentity(quirks.Identity{Manufacturer, Model, PartNumber})`
  and act on the returned `Quirk` fields — SOL payload instance, CD/DVD boot
  aliases, cert-backend fallback chain, boot-override strategy, Samba minimum
  protocol.
- **Certificate deployment is a registry of backends**, not a switch.
  `bmc.RegisterCertFactory(CertBackend, CertManagerFactory)` is called from
  `init()`; the Redfish backend registers from `pkg/bmc` itself, the Supermicro
  ATEN CGI backend from `pkg/bmc/smc` on side-effect import.
  `AutoCertManager` probes the vendor once, resolves a primary, and wires a
  fallback from the resolved quirk's `CertBackendFallback` chain.
- **The trust lifecycle is a ceremony with recorded steps**, not a boolean.
  `App.EnrollBMC` (`pkg/app/bmc_enroll.go`) returns a `BMCEnrollResult` whose
  `Steps []BMCEnrollStep` records every step's outcome — including the ones
  that were skipped, and why. A partial ceremony still returns a complete audit
  trail.

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Shell out to `ipmitool` / `racadm` / `smcipmitool`** | Every vendor tool is a separate binary with a separate packaging story, and none of them exist inside a minimal container image. `pkg/bmc` implements IPMI 2.0 RMCP+ (RAKP handshake, HMAC-SHA1/SHA256 authentication, HMAC-SHA1-96/SHA256-128 integrity, AES-CBC-128 confidentiality) in pure Go with no CGO and no external binaries — stated in `pkg/bmc/doc.go`. |
| **Redfish only** | X10-era ATEN firmware advertises a Redfish service root whose `EthernetInterfaces` collection is empty, whose `CertificateService` rejects uploads, and whose `VirtualMedia.EjectMedia` returns 404. Redfish-only would have stranded the hardware the platform is developed on. |
| **IPMI only** | IPMI has no virtual media, no certificate management, and no structured inventory. The `ipmiClient` therefore lazily constructs an embedded Redfish sub-client (`ensureRedfishClient`, port 443, same credentials and `TLSProvider`) for exactly those operations. |
| **`if vendor == VendorSupermicro` branches inside the control paths** | This is what the code used to do for cert-backend fallback; the comment in `AutoCertManager.wireFallbackBackend` calls the quirk chain "the data-driven replacement for the previous inline `vendor == VendorSupermicro` branch". Adding a board must be a data-only change, or every new board is a new code review of the boot path. |
| **`InsecureSkipVerify` for BMC HTTPS** | It makes the enrollment ceremony meaningless: you cannot pin an identity you never verified. `BuildTLSConfig` returns system roots with TLS 1.2+ when no `TLSProvider` is injected — which *fails* against a self-signed BMC, and the doc comment says that is "the correct secure default". The single permitted `InsecureSkipVerify` in the tree is the capture-only dial in `captureAndConfirmSPKI`, which exchanges no application data and is followed by a pinned reconnect. |
| **Re-upload the backed-up factory certificate on restore** | The platform never holds the factory certificate's private key, so it *cannot*. Restore instructs the BMC firmware to regenerate its own default self-signed certificate; the backup is identity evidence only. |
| **Trust `http-01` for BMC certificate issuance** | BMCs live on isolated management VLANs that ACME servers cannot reach, so `http-01` validation can never succeed. `Config.validateCertBlock` rejects any challenge other than `dns-01` **at config-load time**, so the mistake surfaces as an operator error at boot rather than as a mysterious failure at first renewal. |
| **Enable the Supermicro CGI backend automatically** | The CGI wire protocol was implemented against the SMCIPMITool manual and `httptest` fakes, not against firmware. Auto-mode selection of `smc-cgi` is gated behind `AllowCGIFallback` and returns `ErrAutoCertCGIGated` until an operator clears it. Explicitly pinning `backend: smc-cgi` bypasses the gate — the gate is against *silent* selection, not against use. |
| **A `platformd` proxy for the SOL console** | SOL is a long-lived bidirectional byte stream; there is no request/response shape to proxy. `platformctl bmc console` is standalone-only and says so in its own doc comment. |
| **One credential blob per BMC, overwritten on rotation** | `CredentialStore.Put` creates a *new version* rather than overwriting, and `History` returns ordered versions. Rotation without history means a failed rotation leaves you with no way to reconstruct which password the BMC actually has. |

## 3. Component boundaries

| Piece | Package / path | Owner |
|---|---|---|
| `Client` interface, `ClientFactory`, `ProfileStore`, `Service` | `pkg/bmc/types.go`, `factory.go`, `service.go` | this repo |
| IPMI 2.0 RMCP+ transport, SDR, FRU, SOL | `pkg/bmc/rmcp.go`, `ipmi.go`, `ipmi_sdr.go`, `ipmi_fru.go`, `rmcp_sol.go` | this repo |
| Redfish client and transport | `pkg/bmc/redfish.go`, `redfish_transport.go`, `redfish_types.go` | this repo |
| Vendor probe (`/redfish/v1/`) | `pkg/bmc/vendor.go` | this repo |
| **Vendor quirk registry** | `pkg/quirks/` | this repo |
| Certificate managers and backend registry | `pkg/bmc/cert.go`, `auto_cert.go`, `redfish_cert.go`, `cert_restore.go` | this repo |
| Supermicro ATEN CGI backend | `pkg/bmc/smc/` | this repo |
| Virtual media backend chain | `pkg/bmc/virtualmedia.go`, `vmedia_dispatch.go`, `vmedia_redfish_std.go`, `vmedia_redfish_smc.go`, `vmedia_smc_cgi.go` | this repo |
| Boot-override backends | `pkg/bmc/vboot_smc_oem_ipmi.go` (the `bootOverrideBackends` map in `redfish.go` is the registry; a quirk naming an unregistered strategy fails `SetBootDevice` with `ErrUnknownBootOverrideStrategy`) | this repo |
| User management (IPMI + Redfish) | `pkg/bmc/user.go`, `ipmi_user.go`, `redfish_user.go`, `service_user.go` | this repo |
| Password rotation engine | `pkg/bmc/rotation.go` | this repo |
| Credential types and in-memory store | `pkg/bmc/credentials.go` | this repo |
| MAC / protocol discovery | `pkg/bmc/discovery.go`, `mac_smc_oem_ipmi.go` | this repo |
| Enrollment ceremony | `pkg/app/bmc_enroll.go` | this repo |
| Factory-cert restore ceremony | `pkg/app/bmc_restore.go` | this repo |
| Certificate issuance / renewal wiring | `pkg/app/bmc_cert.go`, `bmc_cert_init.go`, `cert_renewal_handler.go` | this repo |
| Profile → `bmc.Config` adapter | `pkg/api/daemon/bmc_profile_store.go` | this repo |
| gRPC service, REST routes, QUIC handler, MCP tools | `pkg/api/daemon/`, `pkg/webservice/v1/bmc/`, `pkg/api/mcp/bmc_tools.go` | this repo |
| Go SDK client | `sdk/go/services/bmc/` | this repo |
| **Credential persistence at rest** | `pkg/bmc/credentials/quicbaas_store.go` → `go-quicbaas/sdk/go/service` `SecretsService` | **go-quicbaas** |
| **Protected memory for passwords and keys** | `pkg/memguard` wrapper over the stack's abstraction | this repo's wrapper; primitive is the stack's |
| **Certificate issuance (ACME `dns-01`, local CA)** | reached through the stack — see [`docs/ca/`](../ca/) | **not this feature** |
| **The DNS zone A and TLSA records are written into** | [`docs/dns/`](../dns/) | this repo, separate feature |
| **TLS trust strategies (`dane`, `spki`, `ca-file`)** | `pkg/trust` — see [`docs/architecture/bmc-tls.md`](../architecture/bmc-tls.md) | this repo, separate feature |
| **Device profiles that carry BMC connection settings** | `pkg/device/entities` — [`docs/device/`](../device/) | this repo, separate feature |
| **The bootstrap orchestrator that calls enrollment at phase 5a** | `pkg/bootstrap/orchestrator.go` — [`docs/bootstrap/`](../bootstrap/) | this repo, separate feature |

The §R capability row is **"Zero-touch provisioning — BMC (Redfish/IPMI),
iPXE/network boot, installer", Tier 1**, whose SDK surface is `services/bmc`
alongside `services/pxe` and `services/provision`. Tier 1
means all six transports are required; [api.md](api.md) records where that is
not yet true.

`pkg/quirks` **does not import `pkg/bmc`**. Backend names in
`Quirk.CertBackendFallback` and `Quirk.BootOverrideStrategy` are opaque strings
that happen to match `bmc.CertBackend` values; the dependency runs one way only.

## 4. Data flow

### 4.1 A profile-driven operation (`platformctl bmc power-on --profile-id 42`)

```
platformctl  ──HTTPS──▶ platformd REST  /api/v1/bmc/42/power  {"action":"on"}
                            │
                            ├─▶ bmc.Service.PowerOn(ctx, 42)
                            │       │
                            │       ├─▶ clients.Load(42)  ── hit ──▶ cached Client
                            │       │
                            │       └─ miss ─▶ ProfileStore.Get(ctx, 42)
                            │                    │  deviceProfileStore →
                            │                    │  entities.DeviceProfile.BMC
                            │                    │  → *bmc.Config (+ TLSProvider)
                            │                    └─▶ ClientFactory.NewClient(cfg)
                            │                          └─▶ Config.Validate()
                            │
                            └─▶ Client.PowerOn(ctx)
                                   └─ IPMI 2.0 RMCP+ Chassis Control  (UDP 623)
```

The client cache is `sync.Map` with `LoadOrStore`: two concurrent requests for
the same profile may both construct a client, and the loser closes its own copy
rather than taking a lock across a network dial.

**What crosses a host boundary:** the RMCP+ / HTTPS leg to the BMC, on the
out-of-band management network. **What is persisted:** nothing on this path —
`bmc.Service` holds no state beyond the client cache.

### 4.2 The enrollment ceremony (`platformctl bmc enroll --profile-id 7`)

```
platformctl ──gRPC──▶ BMCService.EnrollBMC ──▶ App.EnrollBMC(deviceID, cfg, opts)
                                                  │
  step "trust"               resolve TLS via trust.Resolver (ClassBMC)
  step "factory-cert"        AutoCertManager.GetWebCertificate → live leaf,
                             SPKI SHA-256 + DER SHA-256 captured as metadata
  step "credentials"         CredentialStore.Put("bmc/<name>", Credentials)
  step "replace-certificate" issueBMCCertificateCore: fresh ECDSA key → CSR →
                             ACME dns-01 (or local CA) → AutoCertManager
                             .ReplaceWebCertificate → BMC restarts its web server
  step "dns-register"        A record  <hostname>-bmc.<zone>
  step "dane-publish"        TLSA records for the deployed leaf (and CA)
  step "device-stamp"        Device.BMCEnrollment persisted
```

Every step appends a `BMCEnrollStep{Name, OK, Detail}` whether it ran, was
skipped, or failed. `BMCEnrollResult.FactoryCertPEM` is returned to the caller
and **never written to disk server-side** — the client writes the backup if
`--backups-dir` is set.

### 4.3 Certificate renewal

`initBMCCertManagement` runs at daemon boot only when `bmc.certificate` and
`bmc.key` are both configured. It registers a `CertTarget` in the shared
`CertTargetRegistry`, registers the `platform.cert-renewal` recurring scheduler
job pinned to this node, and then **reconciles** — issuing an initial
certificate only when the BMC is not already carrying the configured one.

That order and that condition both matter:

- **Registration comes before any BMC contact.** A BMC is a remote device that
  can be down or mid-reboot when platformd starts. If registration followed
  issuance, one unreachable BMC would disable certificate renewal for *every*
  target on the node, webservices included. Boot-time issuance failure is
  therefore logged and non-fatal: the target and job are already registered, so
  the next sweep retries.
- **Issuance is conditional on identity, not expiry.** Reissuing is not free on a
  BMC — it regenerates the device key, restarts the web interface, invalidates
  the stored TOFU pin and republishes DANE records. Expiry alone cannot decide
  it, because an unprovisioned BMC presents a long-lived *factory* certificate
  that would read as "not due" indefinitely. So boot compares the deployed
  certificate against the configured subject/SANs
  (`bmcCertMatchesConfiguredIdentity`): a match is left alone for the sweep, a
  factory or foreign certificate is replaced once.

  The match requires **provenance first**: the deployed certificate must chain to
  a trusted root (`App.bmcTrustRoots` — the system pool, covering ACME-issued
  certificates, plus the platform root, covering the local-CA path) with
  `ExtKeyUsageServerAuth`. Names alone prove nothing — anyone can mint a
  self-signed certificate carrying the expected CN and SANs, and accepting it
  would leave the BMC on an unauthenticated certificate indefinitely, since boot
  would skip provisioning and the sweep would report not-due forever. When no
  roots are available the certificate is treated as *not* ours: the cost of being
  wrong is one reissue, whereas trusting an unverifiable certificate is silent
  and permanent.

  Beyond provenance the match is *complete*: the
  subject CN must match and **every** configured DNS/IP SAN must verify. A
  certificate covering only some of the configured names is not the one the
  configuration asked for, and CN equality alone is never sufficient — modern TLS
  ignores CN, so a certificate whose SANs contradict it would fail every client
  handshake while looking provisioned.
- **A failed boot is recovered by the sweep, not stranded.** Because boot-time
  issuance is non-fatal, something has to retry it — and expiry cannot, since a
  factory certificate is valid for years and would be skipped daily forever. The
  BMC `CertTarget` therefore sets `DueOverride`, which reports an identity
  mismatch as due regardless of expiry. `CertTarget.DueOverride` is optional and
  nil for webservice targets, whose served certificate is always one we issued.
`DefaultRotationInterval` for BMC *passwords* is `90 * 24 * time.Hour`,
deliberately matching the ACME certificate cadence.

**Issuer selection.** `(*bmc.Config).validateCertBlock` requires
`certificate.acme.challenge == "dns-01"` whenever a BMC certificate is
configured, so any validated config reaching issuance asked for ACME.

The platform boot wiring therefore sets `RequireACME`: when the BMC declares ACME
and no ACME issuer is available, issuance returns
`ErrBMCACMEIssuerUnavailable` rather than substituting the local CA. Signing the
BMC's certificate with an authority the operator did not select is a trust
decision, not a graceful degradation. Because the renewal handler and job are
registered *before* issuance is attempted, a refusal costs that one target and
never the node's sweep.

`RequireACME` is off by default on the underlying `issueBMCCertificateCore`, so
callers that legitimately accept a local-CA certificate are unaffected.

Both boot paths call `initACMEClientForCertManagement` explicitly, before cert
management runs. Relying on `issueWebServiceCertificate`'s side effect is not
enough even on the webservices path: an ordinary restart finds the certificate
already in the CA and jumps to `certLoaded`, skipping issuance — the same restart
path that used to leave the cert-target registry empty also leaves
`App.ACMEClient` nil.

The issuer is additionally resolved **lazily**, at issuance time, via
`ACMEIssuerFunc`. The renewal target's `Reissue` closure captures its options by
value, so an issuer captured while still nil would stay nil for the life of the
process and every scheduled retry would fail identically — the BMC could never
converge.

Renewal runs a two-phase DANE rollover (RFC 7671 §8.1): `OnCertIssued`
pre-publishes the new DANE-EE TLSA record *before* deployment, `OnCertDeployed`
updates the stored SPKI pin and re-publishes the full TLSA set. Both hooks are
non-fatal — a certificate that is already on the BMC is not un-deployed because
DNS was briefly unavailable.

### 4.4 Password rotation

`RotationEngine.RotateOnce` is **store-ahead**: the new password is written to
the credential store *before* it is applied to the BMC, so the store always
reflects the best guess at real BMC state. Apply → verify with a fresh session →
on failure, roll back and re-store the old password. The four failure outcomes
are separate error types precisely because their operator response differs;
see [engineering.md](engineering.md) §6.

## 5. Trust boundaries

1. **BMC credentials are a trust boundary.** A BMC account is full physical
   control of the host: power, boot device, virtual media, serial console. Whoever
   holds it can boot arbitrary media on the machine. Consequences that follow
   from that and are enforced in code:
   - Passwords and TLS private keys are `*memguard.Secret` across every API
     boundary — `UserManager.CreateUser`/`SetUserPassword`,
     `CertificateManager.ReplaceWebCertificate`, `PasswordGenerator`. Raw
     `string`/`[]byte` passwords are not part of the public API.
   - `Config.Password` and `Config.EncryptionKey` carry `secret:"true"` struct
     tags. Config values use `kms://` references, not literals.
   - At rest, credentials live in the QuicBaaS secrets service via
     `credentials.QuicBaaSStore` at path `bmc/<name>`, versioned.
   - `--bmc-pass-file` is rejected unless the file mode is `0600` or stricter
     (`ErrBMCInsecurePasswordFile`).
2. **The BMC's TLS identity is a trust boundary.** Until enrollment runs, the
   platform is talking to a self-signed certificate. `trust.ClassBMC` resolves
   through an ordered strategy chain (`dane`, `spki`, `ca-file`). First
   contact is `spki` with a `bmc_spki_pin` — `tofu` is NOT available for the
   bmc class, because it fetches a CA bundle and a BMC serves none (#83,
   upstream go-xkms#139). The enrollment ceremony is what makes moving off a
   hand-supplied pin to TLSA records possible.
3. **Standalone mode has no audit log and no profile persistence.** The
   `--bmc-host` path talks straight to hardware, bypassing `platformd` entirely.
   Its own flag help says so. Everything done there is invisible to the platform.
4. **The factory certificate backup is identity evidence, not a spare key.** The
   platform never holds its private key. It proves what the BMC's identity was at
   enrollment time; it can never be re-deployed.
5. **Virtual media is remote code execution by design.** Mounting an ISO and
   setting the boot device is how the platform installs an operating system. The
   same two calls are how an attacker installs one. `MediaSpec` carries its own
   `Username`/`Password` for CIFS/NFS shares — those are credentials too.
6. **The IPMI client silently opens a second, HTTPS connection.** Virtual media,
   `VirtualMediaStatus` and `ClearUEFIBootEntries` on an `ipmiClient` construct an
   embedded Redfish client on port 443 with the same credentials. Anyone modelling
   the firewall from `protocol: ipmi` alone will get it wrong.

## 6. What this feature deliberately does not do

- **It does not issue certificates.** The CA does, through the stack. This
  feature builds the CSR, chooses the backend, and deploys the result.
- **It does not own DNS or DANE.** It calls the platform DNS service. TLSA
  publication failure is recorded and non-fatal, because the certificate is
  already on the BMC by then.
- **It does not decide trust strategy.** `pkg/trust` resolves `ClassBMC`;
  `pkg/bmc` only accepts an injected `TLSProvider` and fails closed to system
  roots when none is given.
- **It does not manage the host operating system.** Everything here is
  out-of-band. Installer, PXE and provisioning workflows are separate features.
- **It does not proxy the serial console.** SOL is standalone-only; there is no
  `platformd` endpoint and no plan recorded in code for one.
- **It does not schedule password rotation.** `RotationEngine.RotateOnce`
  rotates once. `DefaultRotationInterval` is a constant the caller may use; no
  code in the tree registers a recurring BMC-password job. The legacy README's
  "automatic 90-day password rotation" overstates what is wired — see §9.
- **It does not implement BMC hardware attestation.** `pkg/bmc/attestation`
  defines `AttestationProvider`, `Evidence`, `Policy`, `Verifier`, a vendor
  dispatch registry and three backends — and **nothing in the platform imports
  it**. `pkg/bmc/CLAUDE.md` calls it "preserved scaffolding, no real
  implementation until RoT-capable hardware available".
- **It does not expose a BMC surface on the embedded transport.**
  `ServiceRegistry` in `sdk/go/transport/embedded/adapter.go` has no `BMC`
  field, so `--transport embedded` cannot reach any BMC capability. Recorded as
  a Tier-1 gap in [api.md](api.md), not chosen.

## 7. Vendor quirks — how a board gets supported

`quirks.ResolveIdentity(quirks.Identity{Manufacturer, Model, PartNumber})`
picks the **most specific** entry for the manufacturer: an entry whose model
key equals `System.Model` beats one whose model key is a substring of it or
whose part-number prefix matches `System.PartNumber`; among those the longer
key wins; any board-specific entry beats the manufacturer-wide entry, which
beats `quirks.Default()`. Declaration order only breaks exact ties, so a
narrower entry may be added after the broader one it refines without being
shadowed. Matching is case-insensitive; `ResolveIdentity` always returns a
valid `Quirk`, so callers never nil-check. `quirks.Resolve(manufacturer,
model)` is the same lookup with no part number, for callers that have none
(`AutoCertManager`, which knows only the vendor probe result).

The part-number matcher exists because some firmware does not name the board
in `Model`: the mini fleet's ATEN FW 4.00 / BIOS 2.6 BMCs serve
`Manufacturer: Supermicro`, `Model: Super Server`, `SKU: To be filled by
O.E.M.`, and only `PartNumber: SYS-5018D-FN8T-AS001` identifies the X10SDV
board. Every `Quirk` carries an informational `Key` (`supermicro`,
`supermicro/x10sdv`, `default`, …), and both clients log the entry they
resolved at `Info` once per client so a run log shows which one won:

- **Redfish client** — identity from `System.Manufacturer` / `Model` /
  `PartNumber`, cached at discovery (`bmc: resolved vendor quirk`).
  `SetBootDevice` re-reads the same three fields from the system resource it
  fetches (`systemIdentity`).
- **IPMI client** — identity from IPMI alone, no Redfish and no TLS (the path
  that must keep working on an already-provisioned X10): the vendor from the
  Get Device ID IANA enterprise number, the board from the FRU **Board
  Product** field and the SKU from the FRU **Product Part Number** field
  (`hardwareIdentity`, logged as `bmc: resolved vendor quirk (ipmi path)`).
  Either FRU field names the board, so boot-override dispatch and the SOL
  payload instance resolve the same entry Redfish discovery would. The
  identity is cached once per client with a compare-and-swap. Only a
  definitive answer is cached: a decoded FRU, an unknown IANA number, FRU
  content that does not decode, or a completion code that says the FRU can
  never be read here (`0xC1` invalid command, `0xC9` out of range, `0xCB`
  data not present, `0xCC` invalid field, `0xD4` privilege — vendor-only
  identity). A transport failure or a state-dependent completion code
  (`0xC0` busy, `0xC3` timeout, `0xD3` unavailable, …) is never cached and
  is retried on the next call.
- **Installer** — `installer.Config` carries `hardware-manufacturer`,
  `hardware-model` and `hardware-part-number`, propagated to `OSConfig`, so
  the UKI cmdline and the Alpine installer resolve the same entry as the BMC
  side. The bootstrap orchestrator populates them from
  `bmc.Client.HardwareIdentity` at discovery time (see
  [`docs/architecture/vendor-quirks.md`](../architecture/vendor-quirks.md)).
- **Redfish discovery caching** — success latches permanently; a failure is
  reused for `discoveryFailureTTL` (60s) and then retried. Discovery gates
  eight operations on the client, several called from polling loops
  (`waitForPowerOff` polls `PowerStatus` 20 times at 5s intervals), so
  retrying unconditionally would make each iteration pay a full discovery
  timeout — up to the 30s HTTP client timeout against a BMC that accepts TCP
  and then hangs — turning one wait into minutes. At 60s that loop pays at
  most two extra attempts. A `sync.Once` was the other extreme: it cached the
  failure forever, so one service-root blip made the client permanently
  useless for power, boot, virtual media and sensors alike.
  `HardwareIdentity` deliberately bypasses the negative cache
  (`discoverFresh`) because the bootstrap layer retries it, bounded, once per
  node and not in a loop. A successful fresh discovery latches for every
  gated call, so the bootstrap layer reads the identity *before*
  `GetSystemInfo`: system info then rides a discovery the identity retry
  recovered instead of the cached failure (#206,
  `TestRedfishClient_GetSystemInfo_RidesDiscoveryRecoveredByIdentity`).
- **`Client.HardwareIdentity`** — returns the `quirks.Identity` the client
  itself resolves from, so a caller lands on that client's registry entry
  and no other. It is deliberately not `SystemInfo`: over IPMI,
  `SystemInfo.Manufacturer` is the raw IANA enterprise number (or the FRU
  Product Manufacturer) and `SystemInfo.Product` is the FRU Product Name,
  while the quirk identity is the vendor name derived from that number plus
  the FRU Board Product and Product Part Number. An identity rebuilt from
  `SystemInfo` resolves a different entry — see
  `TestIPMIClient_HardwareIdentity_DivergesFromSystemInfo`. In-process only:
  the method is on the Go `Client` interface and appears on no wire surface,
  so `SystemInfo` and the six transports are unchanged.

Registered entries (`pkg/quirks/registry.go`), with what each actually changes:

| Key | Matched by | What the entry exists for |
|---|---|---|
| `supermicro` (manufacturer-wide) | `Manufacturer` | SMB1 (`NT1`) and unencrypted SMB for virtual media; `CD/DVD` BIOS alias and `UefiUsbCd` UEFI alias; `["redfish","smc-cgi"]` cert fallback chain; `VmediaRedfishOEMFallback`; `BootOverrideContinuous`; `BootOverrideStrategy: "smc-oem-ipmi"` |
| `supermicro/x10sdv` | `Model` contains `x10sdv`, or `PartNumber` starts with `SYS-5018D-FN` (SYS-5018D-FN8T = X10SDV-TP8F, SYS-5018D-FN4T = X10SDV-TLN4F; the rest of the 5018D family is X10SLM-F and stays manufacturer-wide) | Everything above; SOL is on COM1 like the manufacturer-wide entry (`SOLPort: "ttyS0"`, `SOLPayloadInstance: 0x01`, `earlycon` at `0x3f8`, `console=ttyS0` last). Measured 2026-08-29 on node-02 (`SYS-5018D-FN8T-AS001`, ATEN FW 4.00): kernel printk, autoinstall, platform-initrd and OpenRC output all appeared on payload instance 1, instance 2 activated and stayed silent; the entry previously claimed COM2 / instance 2 / `0x2f8`, which was wrong for this board. BIOS POST is not redirected to SOL. The entry exists for the part-number identity match (above), the VeloCloud alias, and the X10 boot-override trap. `BootOverrideStrategy: "smc-oem-ipmi"` is the only registered strategy |
| `velocloud networks, inc.` | `Manufacturer` | A Supermicro X10SDV board under an OEM SMBIOS skin. Without this entry `Resolve` returns `Default()` and the X10 boot-override trap applies |
| `aspeed` | `Manufacturer` | `8250_aspeed_vuart` kernel module and SOL on `ttyS4` |
| `dell inc.` | `Manufacturer` | COM1 SOL, SMB2, encryption required, no cert fallback chain |
| `hpe` | `Manufacturer` | Same shape as Dell |

Two quirk fields, and the clear that undoes one of them, deserve their own
note because they encode failure modes that are invisible without them:

- **`SOLPayloadInstance`.** Activating IPMI SOL payload instance `0x01` against a
  board wired to `0x02` *succeeds at the protocol level* and then streams zero
  bytes. The operator sees an empty console log and no error. The quirk supplies
  the right instance; `Config.SOLPayloadInstance` (and `--sol-instance`) is the
  operator override for hardware that has no quirk entry yet.
- **CD/DVD alias order follows the host's boot mode.** `SetBootDevice` reads
  `Boot.BootSourceOverrideMode` from the system resource it fetches and orders
  the CD/virtual-media candidates accordingly: `UEFI` → the UEFI group first
  (vendor `UEFICDAlias`, then DMTF `UefiCd`), then the Legacy group (vendor
  `CDDVDAlias`, then `Cd`); `Legacy` → the Legacy group first; no or unknown
  mode → the historical order (vendor UEFI alias, vendor Legacy alias, DMTF
  `UefiCd`, `Cd`). USB-CD fallbacks stay last in every mode, and non-CD
  targets are unaffected. Without this a UEFI-only board advertising `UefiCd`
  but not `UefiUsbCd` was PATCHed to the Legacy `CD/DVD` alias, which its
  firmware ignores, and the node booted from disk.
- **`BootOverrideContinuous`.** X10 ATEN firmware erases a `Once` boot override
  before BIOS POST reads it, so the node falls through to the on-disk UEFI entry
  and the install never starts. `Continuous` is the only mode that survives the
  reset cycle; the orchestrator clears it explicitly afterwards with
  `SetBootDevice(None, false)`.
- **`SetBootDevice(None)` clears both layers.** `BootDeviceNone` always sends
  the Redfish PATCH `BootSourceOverrideTarget=None` /
  `BootSourceOverrideEnabled=Disabled` — never `Once`/`Continuous`, and the
  quirk's Continuous forcing does not apply to it. When the vendor strategy is
  `smc-oem-ipmi`, the OEM disable (`0x30/0x70/0x0c/0x01/0x00`) is sent first
  and the clear then *continues* to the PATCH instead of returning, on both the
  Redfish and the IPMI dispatch path. Measured on node-02 (ATEN FW 4.00, BIOS
  2.6): the OEM disable alone leaves `Continuous UefiUsbCd` armed in the Redfish
  view and "Force Boot from remotely connected CD/DVD" in the IPMI view; the
  PATCH clears both. Because the PATCH is the step that disarms the override,
  a clear is never best-effort: an OEM-disable failure (or, on the IPMI path,
  a standard boot-flags failure) still runs the PATCH and is reported
  afterwards, and on the IPMI path a Redfish failure on the clear is an error
  rather than the warning a boot-target reinforcement gets.
  For every other device a successful OEM override remains authoritative and
  the PATCH is skipped.

## 8. Deployment shapes

| Shape | How BMC config is resolved | What is reachable |
|---|---|---|
| **Daemon, profile-driven** | `deviceProfileStore` maps `entities.DeviceProfile.BMC` → `*bmc.Config`, injecting the platform `TLSProvider` | Everything except SOL console and MAC discovery |
| **Daemon, node-local identity** | Top-level `bmc:` block in the platformd YAML → `app.BMCConfig` (`*bmc.Config`) | Certificate issuance, deployment and scheduled renewal for *this node's own* BMC |
| **Standalone (`--bmc-host`)** | Built in-process from CLI flags (`newStandaloneConfig`) | Power, boot device, virtual media, sensors, system info, cert get/replace, users, SOL console, MAC discovery. No audit log, no persistence |

These two config paths carry **different field sets**, and conflating them is
the most common mistake this document exists to prevent — see
[engineering.md](engineering.md) §3.

## 9. Corrections to the legacy documents in this folder

The legacy files stay in place; these are the points where they contradict the
code as of 2026-08-18.

| Legacy claim | Location | What the code does |
|---|---|---|
| "CLI commands under `pkg/cli/commands/bmc` use this SDK exclusively" | `sdk.md` | Only `bmc cert get/status/replace`, `bmc enroll` and `bmc cert restore` use the SDK. `power-*`, `set-boot-device`, `get-boot-device`, `mount-iso`, `unmount-iso`, `media-status`, `sensors`, `system-info`, `provision` build a raw `*http.Client` and call `/api/v1/bmc/...` directly (`pkg/cli/commands/bmc/helpers.go`) |
| "Clients are created on demand using the `ClientFactory`" (implying protocol dispatch) | `README.md` | The daemon constructs the service with `bmc.NewIPMIClientFactory` (`pkg/api/daemon/daemon.go`), whose `NewClient` **ignores `Config.Protocol`** and always returns an IPMI client. `NewDefaultClientFactory` — which does dispatch on protocol — is used by the standalone CLI path, not the daemon |
| `password: "vault://bmc/..."` | `configuration.md` | `vault://` appears nowhere in `pkg/`. The secret-reference scheme is `kms://`, e.g. `kms://bmc/password?ensure=true&len=16&enc=base64` |
| `enrollment:`, `certificate:`, `key:`, `backend:`, `allow_cgi_fallback` shown as **device-profile** fields | `configuration.md` | `entities.BMCConfig` has exactly five fields: `address`, `port`, `username`, `password`, `protocol`. Those other keys belong to `bmc.Config`, which is populated from the top-level `bmc:` block of the platformd YAML — not from a device profile |
| `acme.request.authz_type` / `challenge_type` | `configuration.md` | The validated field is `Certificate.ACME.Challenge`; `validateCertBlock` requires it to equal `dns-01` |
| REST endpoint table lists 13 routes, omitting cert and user routes | `operations.md` | The daemon registers 20 route entries covering 17 distinct paths, including `GET/PUT /bmc/{profileID}/cert` and five `/users` routes |
| "All five transports expose the enrollment operation" | `operations.md` | Four do: REST, gRPC, Unix (gRPC over UDS), QUIC, MCP — that is five *listed*, but **embedded is a sixth transport and has no BMC route at all** (`ServiceRegistry` has no `BMC` field). Enrollment is a Tier-1 capability missing one required transport |
| "automatic 90-day password rotation" as a shipped capability | `README.md` | `DefaultRotationInterval` is defined and `RotationEngine.RotateOnce` works, but no scheduler job registers rotation. Only *certificate* renewal is scheduled (`RegisterCertRenewal`) |
| `--output-format json` | `operations.md` | The global output flag is `--output` / `-o`; `platformctl` uses `cli.CommonFlags.OutputFormat` behind it |
| `platformctl bmc cert restore --profile-id 7 --factory` documented under "Factory Certificate Restore" only | `operations.md` | Correct, and worth keeping: `--factory` is a required explicit flag with no default, present solely to make accidental invocation impossible |
| Example hosts use routable-looking internal addresses | `operations.md`, `configuration.md` | This folder ships to GitHub. Use `bmc.example.com`, `platform.example.com`, `<install-dir>` |

## 10. Related

- [engineering.md](engineering.md) — exported surface, invariants, errors, config, tests
- [cli.md](cli.md) — every verb and flag
- [api.md](api.md) — every capability on all six transports
- [user.md](user.md) — task-oriented usage
- [`docs/architecture/bmc-tls.md`](../architecture/bmc-tls.md) — the certificate lifecycle in full
- [`docs/architecture/vendor-quirks.md`](../architecture/vendor-quirks.md) — the quirk registry's own design note
- [`docs/architecture/bmc-attestation.md`](../architecture/bmc-attestation.md) — the unwired attestation scaffolding
- [`docs/daemon/api.md`](../daemon/api.md) — transports, QUIC opcodes, status bytes, authorization
- [`docs/bootstrap/`](../bootstrap/) — the orchestrator that calls enrollment at phase 5a
- [`docs/device/`](../device/) — device templates and profiles
