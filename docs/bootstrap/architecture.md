# Bootstrap — Architecture

> **Status: NORMATIVE** · Scope: `pkg/bootstrap/`, `pkg/firstboot/`, `pkg/boot/`, the barrier/seal touchpoints in `pkg/barrier/` and `pkg/api/rest/init_handlers.go` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> **Scope note.** The legacy files in this folder — [overview.md](overview.md),
> [day-zero.md](day-zero.md), [dane.md](dane.md), [deployer.md](deployer.md),
> [config-delivery.md](config-delivery.md), [config-reference.md](config-reference.md),
> [pxe-bootstrap.md](pxe-bootstrap.md), [manual-nodes.md](manual-nodes.md),
> [switch-management.md](switch-management.md), [configuration.md](configuration.md),
> [api-reference-rest.md](api-reference-rest.md), [README.md](README.md) — predate
> this convention. They remain in place and still carry useful narrative. Where
> they disagree with these five files, these five win, and the corrections are
> listed in [engineering.md](engineering.md) §12.

---

## The problem

Bootstrap is where a machine that the platform has never seen becomes a machine
the platform trusts. Two chicken-and-egg problems meet here, and they are
different problems:

1. **Trust before trust.** A node cannot verify the platform's TLS certificate
   until it holds the platform CA bundle, and it cannot fetch the CA bundle over
   a verified channel until it holds the CA bundle. Something outside the CA
   chain has to break the loop.
2. **Identity before an operating system.** A racked, powered-off machine has no
   OS, no keys, and no way to be told anything except through its board
   management controller or the network it happens to boot from. The platform
   must drive it from nothing to a node that seals its own disk key into its own
   TPM, without an operator logging in.

A design that solves only the first is a trust library. A design that solves only
the second is a provisioning tool. Bootstrap is the seam where both are solved
in one ordering, because the ordering *is* the security property: the node must
receive trust material before it can ask for anything, and the platform must not
accept anything the node says about itself until an out-of-band identity exists.

## The shape chosen

Three layers, deliberately kept separable so each can fail loudly on its own.

### 1. Day-zero orchestration — outside-in, from an operator workstation

`bootstrap.Orchestrator` runs a fixed, named phase sequence against a fleet
described by one `bootstrap.yaml`. Phases are constants in the code
(`phaseDiscovery`, `phaseSwitch`, `phaseDeploy`, `phaseControlPlane`,
`phaseSeed`, `phaseRemaining`, `phaseBMCEnroll`, `phaseHealthGate`,
`phaseTeardown`), and `BootstrapResult.Phase` always names the phase that was
running when the run stopped.

The control plane is provisioned **first and alone**, because everything after
it — device templates, per-node profiles, BMC enrollment, health verification —
is served *by* the control plane. Gateways and workers only start once the
control plane answers.

### 2. Node first boot — inside-out, from an encrypted installer container

`firstboot.FirstbootSealStrategy` runs in the initramfs of a freshly installed
node. Every provisioning artefact is produced **inside** a LUKS container
(`installer.luks`) that the installer left on the EFI partition, so no plaintext
key or platform state is ever written to unencrypted storage. Only after the
LUKS root is unlocked are the contents copied out, and only after sealing
succeeds is the container securely wiped.

### 3. Trust establishment — several independent channels, none of them implicit

`pkg/trust` (documented under [`docs/ca/`](../ca/) and
[`docs/dns/dane.md`](../dns/dane.md) for the DANE half) resolves an **ordered
strategy chain** per trust class. Bootstrap owns the platform-side publication
and serving of that material: TLSA records (`bootstrap.DANEPublisher`), the
Noise_NK listener (`pkg/api/noise`, fed by `bootstrap.CABundleAdapter`), and the
unauthenticated PEM endpoint `GET /api/v1/ca/bootstrap`.

#### Deploy constraint: the Noise bootstrap wire has no cross-version compatibility

**A rolling upgrade across a change of the underlying bootstrap wire is not
possible. The control plane and the nodes must be deployed together.**

go-truststrap 0.3.0 put a two-byte `version||suite` header ahead of the client's
first frame and bound those bytes into the handshake transcript as the Noise
prologue. A 0.4 server therefore rejects a 0.2-era client's bare Noise message
twice over: the header check fails, and the transcript would not match even if
the leading bytes happened to line up. Both ends of this wire are the platform
itself — a node fetching a CA bundle from the control plane — so there is no
third party to negotiate with and no compatibility window to stage through.

Treat any change of the truststrap generation as a fleet flag day, and check the
pin before planning a partial rollout. The platform moved from 0.2.0-alpha to
0.4.0-alpha with the go-quicbaas v0.7.0-alpha pin (#517).

### Alternatives rejected

| Alternative | Why it was rejected |
|---|---|
| **Trust-on-first-use as an implicit fallback for the CA bundle** | A silent TOFU fallback means the weakest channel is the one that runs when the strong ones are merely misconfigured. `tofu` must appear explicitly in a scope's `strategies` chain, and a scope that lists it without a pin store fails construction rather than degrading. |
| **`InsecureSkipVerify` when fetching the control plane's own CA bundle** | The bundle *is* the trust anchor, so there is nothing to verify against at handshake time — but "nothing to verify against" is not the same as "verify nothing". `fetchControlPlaneCABundle` captures the served chain in `VerifyConnection` and then verifies that chain **against the bundle it just downloaded**, rejecting a mismatch with `ErrCABundleVerifyFailed`. `SessionTicketsDisabled` is set so a resumed session cannot skip the capture. The capture also has to happen **before** the control plane's own post-install health probe: the probe verifies with ordinary chain validation, so probing before the bundle is captured judges a self-provisioned CA against the system pool and fails for the whole window (#107). `awaitPostInstallHealth` therefore captures first — retrying "not up yet" failures on the health cadence — and probes only once the pool is in place. |
| **Trust-on-first-use for the deployer and switch SSH host keys** | The deployer host runs the DHCP/TFTP/HTTP services every node boots from; accepting its host key blindly puts the whole fleet's install path behind an unauthenticated first contact. `deployer.NewSSHClient` fails closed when `known_hosts_path` is empty — there is no TOFU path at all. |
| **Persisting BMC pins to disk** | A persisted pin is a long-lived credential nobody rotates. BMC pins live in an in-memory store for the lifetime of that `platformctl bootstrap run` process only; SPKI pins are public-key hashes, so nothing is lost by discarding them. (This originally described TOFU-captured pins; tofu is not available for the bmc class — #83 — so today the pin comes from `bmc_spki_pin`.) |
| **Requiring a BMC on every node** | It would make the same automation unusable for a machine with no out-of-band controller. `BoardController` is the board-agnostic contract and `hasBoardManagement` is the single predicate; a node without a management block gets **zero** hardware operations and is observed rather than driven. |
| **Skipping BMC MAC discovery when the operator listed MACs in YAML** | On a multi-NIC host the operator usually lists the PXE MAC, while the installed OS enumerates a different NIC as `eth0`. Every per-MAC lookup downstream then misses. Discovery takes the **union** of declared and discovered MACs, operator values first. |
| **Keying installer config by hostname** | The node does not know its hostname yet — that is what it is fetching. Config is keyed by MAC and published under **every** known MAC, so the fetch succeeds whichever NIC came up first. |
| **Storing the LUKS key as a plain file on the EFI partition** | The EFI partition is unencrypted and readable by anyone with the disk. The key exists only inside `installer.luks`; `firstboot.Executor.Run` returns `ErrNoLUKSKey` rather than falling back to a plain key file. |
| **Using the `pcr-banks` file as the "already provisioned" marker** | `pcr-banks` is written on every successful install boot, before sealing has necessarily completed, so treating it as a marker silently skips TPM provisioning — and therefore the enrollment ceremony — on every fresh first boot. The marker is `seal-platform.pub`, which only exists once a platform seal was actually written. |
| **Setting the TPM hierarchy auth to a PIN generated during first boot** | The PIN is discarded when first boot exits, so every later operation that needs owner-hierarchy auth fails. `Install` is called with a nil SO PIN; hierarchy auth is left empty and the protection boundary is the per-key SRK auth the daemon sets later. |
| **Deleting `luks-key.bin` as soon as the seal is written** | The seal has not been *proved* until a clean reboot unseals with it. Deleting the key first leaves a machine with no fallback if the next boot's PCR policy does not match. The key is preserved pending a seal-confirmation handshake, and the cost — key plaintext inside an encrypted container — is accepted deliberately. |
| **Returning success when sealing fell back to a plain-key unlock** | The machine boots, so it looks fine, and the daemon then fails at startup with a policy error nobody connects to the install. `ErrSealingFallbackUsed` makes the fallback a non-zero exit so the init service does not mark itself started and first boot re-runs. |
| **Rebooting automatically to verify the PCR seal** | On hardware where a PCR differs between the installer and production initramfs, every verify-reboot fails, falls back, and fires another verify-reboot. Verification is deferred to the next operator-initiated reboot; the keyfile fallback covers the gap. |
| **Tearing down the bootstrap container as soon as the last node installs** | The container is usually the only DHCP/DNS provider on the provisioning network. Teardown runs only after `controlPlaneHealthGate` confirms every control-plane node is serving; a failed gate skips teardown rather than stranding the fleet. |
| **Aborting the run when BMC enrollment fails** | Enrollment is a post-install ceremony, not a precondition for a working node. Failures are recorded per node in `BootstrapResult.BMCEnrollments` and logged as warnings; the operator retries with the BMC CLI. |
| **One shared BMC TLS provider for the whole fleet** | Each BMC presents its own (usually self-signed, often expired) certificate, so one provider cannot carry every node's pin. A node that declares `bmc_spki_pin` or `bmc_trust` gets a node-scoped provider; nodes that declare neither share the run-scoped one. (The run-scoped provider was also meant to preserve TOFU pin continuity across re-contacted BMCs — that never worked, because tofu is a CA-bundle fetch rather than endpoint pinning, and it is no longer allowed for the bmc class; see #83 and go-xkms#139.) |

## Component boundaries

| Piece | Package / file | Owner |
|---|---|---|
| Day-zero orchestration, phase sequencing, results | `pkg/bootstrap/orchestrator.go` | this repo |
| Dry-run planning | `pkg/bootstrap/orchestrator_dryrun.go` | this repo |
| `bootstrap.yaml` schema, load, validation | `pkg/bootstrap/pxe_config.go` | this repo |
| Node discovery (MAC union, system info) | `pkg/bootstrap/discovery.go` | this repo |
| Board-agnostic hardware contract | `pkg/bootstrap/board_controller.go` | this repo |
| Virtual-media boot, install-log observation, CP bundle/pin capture | `pkg/bootstrap/virtual_media.go`, `install_log_poller.go`, `iso_stager.go` | this repo |
| Template/profile seeding to the control plane | `pkg/bootstrap/seeder.go` | this repo |
| Node-identity injection into merged device config | `pkg/bootstrap/config_inheritance.go` | this repo |
| Bootstrap container manifest and deployment | `pkg/bootstrap/container/`, `pkg/bootstrap/deployer/`, `deployer_adapter.go` | this repo |
| **DANE TLSA publication and RFC 7671 rollover** | `pkg/bootstrap/dane_publisher.go`, `rollover.go` | this repo |
| TLS certificate hot-reload | `pkg/bootstrap/cert_reloader.go` | this repo |
| CA-bundle provider for the Noise listener | `pkg/bootstrap/bundle_provider.go` | this repo |
| Noise_NK bootstrap listener | `pkg/api/noise/` | this repo (wraps the stack's canonical Noise server) |
| Secret-URI scheme vocabulary, config rewriting | `pkg/bootstrap/secrets.go`, `config_writer.go` | this repo |
| Node first boot: seal, provision, copy-out, wipe | `pkg/firstboot/strategy.go`, `executor.go` | this repo |
| Initramfs unlock and recovery commands | `pkg/boot/commands/`, `pkg/boot/config/` | this repo |
| **Barrier lifecycle (init / unseal / seal / rekey / ceremony)** | `pkg/barrier/` — a thin wrapper over the SDK | **not this repo**; the barrier and ceremony are qrdb-owned, consumed through `go-quicbaas/sdk/go` `Security().Barrier()` / `Security().Ceremony()` |
| Pre-unseal minimal REST surface (`/healthz`, `/init`, `/unseal`) | `pkg/api/rest/init_handlers.go` | this repo |
| **Trust strategy dispatch, per-strategy fetch, caching** | `pkg/trust/` is a thin platform wrapper | **not this repo**; the generic resolver and the DANE/Noise/SPKI primitives are xkms-owned, reached through the quicbaas SDK re-export |
| **CA issuance and the authenticated bundle route** | [`docs/ca/`](../ca/) | this repo, separate feature |
| **iPXE/HTTP boot server, ISO build, installer** | [`docs/provisioning/`](../provisioning/) | this repo, separate feature |
| **BMC protocol, vendor quirks, enrollment ceremony** | [`docs/bmc/`](../bmc/) | this repo, separate feature |
| **Physical switch configuration** | `pkg/switch/` — see [switch-management.md](switch-management.md) | this repo, separate feature |
| **DNS zones and DNSSEC signing** | [`docs/dns/`](../dns/) | this repo, separate feature |

The ownership-register (`docs/00` §R) rows this feature touches are the
platform's *zero-touch provisioning* row (shared
with [`docs/provisioning/`](../provisioning/)) and, at its lower edge, the
qrdb-owned *barrier/seal* and *firstboot/bootstrap* rows — consumed strictly
through `go-quicbaas/sdk/go`, never reimplemented here. `pkg/barrier` and
`pkg/trust` are wrappers over that SDK edge; if either grows behaviour the SDK
does not have, that is a boundary defect, not a feature.

## Data flow — day zero through first boot

### Phase 0 · Discovery

`DiscoverNodes` walks `bootstrap.yaml`'s `nodes:` concurrently. A node with
`bmc_address` gets protocol detection (or the declared `redfish`/`ipmi`), MAC
discovery, and best-effort system info. A node with `macs:` and no BMC is taken
as declared. A node with `skip_install: true` is passed through untouched.
Discovered MACs are the **union** of YAML and BMC values, operator values first.

### Phase 1 · Switch (optional)

Only when `switch:` is present. VLANs and port assignments are pushed over an
SSH session whose host key must already be pinned.

### Phase 2 · Deploy the bootstrap container

The manifest (MAC → role → hostname) is written to a temp file, SCP'd to the
deployer host, and a container is started with the host data directory
bind-mounted at `/data`. It serves DHCP, TFTP, HTTP (`:8080`) and, for
virtual-media installs, an SMB share. `redeploy_mode` decides whether an
existing container is reused (`if-stale`, the default), always replaced
(`always`), or treated as an error (`never`).

### Phase 3 · Control plane

Control-plane nodes are provisioned concurrently. Per node, the boot method
selects the path:

- **`pxe` with board management** — one-shot PXE boot override, power cycle if
  already on, wait for the install log, switch to persistent disk boot, power on
  from the post-install poweroff, wait for health.
- **`virtual-media`** — stage the ISO on the deployer host, mount it over SMB on
  the BMC, one-shot CD boot, power reset, wait for the install log, unmount, disk
  boot, power on, wait for health. Retries when the node is observed booting from
  disk instead of the ISO.
- **No board management** — publish per-MAC config, then *observe only*. The node
  reaches the installer on its own boot order and self-boots the installed OS.

Health is not "the installer said so". The install log is the installer's own
report; health is a separate HTTPS probe of the running daemon.

For a control-plane node the probe's trust anchor is the CA that node
self-provisioned moments earlier, so the wait is two steps in a fixed order:
capture-then-verify the CA bundle (retrying a refused connection or an HTTP
error until the health deadline — that is a node still booting), then probe
`/api/v1/status` against the captured pool. A bundle the served chain does not
verify against ends the wait immediately (`ErrCABundleVerifyFailed`). Whatever
ends the wait, the error names the last capture or probe failure, not only the
deadline.

The CA bundle — the trust anchor — is captured only from the control plane's
operator-declared static IPv4 in the bootstrap config; a control plane without
one is rejected at discovery. The IP the node reports in `registration.json` is
never used for that: it arrives over an unauthenticated PUT, and capture-then-
verify can only prove a bundle matches the endpoint that served it. Once the pool
is pinned, connections dial the control plane wherever it is reachable — the
`registration.json` IP, the static IPv4, then the hostname — and every one of
them verifies against that pool. The certificate is verified against the control
plane's **DNS name**: identity certificates carry DNS SANs only, never the address
a node happens to listen on. Every orchestrator TLS client that reaches the
control plane (bundle capture, health probe, seeder, SPKI pin capture, the
pre-teardown health gate) therefore asks for one name, read once from the merged
control-plane config the orchestrator itself stages (the public webservice's
certificate subject CN, else its first DNS SAN) with `cp.<platform domain>` as
the logged fallback.

### Phase 3a · Node first boot (on the node, concurrent with the wait above)

1. Mount the EFI partition read-write; detect first boot by
   `installer.luks` present **and** `seal-platform.pub` absent.
2. Open `installer.luks`; read the 32-byte LUKS key and the recovery key.
3. Provision the TPM fully — factory reset (optionally a destructive clear),
   then EK + shared SRK + platform policy + IAK (+ IDevID when an EK
   certificate exists), and create the **Platform KeyStore SRK** at its
   configured handle (default `0x81000002`) through the same `pkg/platform`
   keychain path platformd uses. First boot runs from the installed system,
   so PCR 7/9 already hold their production values and the platform policy
   captured here is the one every later boot reproduces. platformd then
   finds a fully-provisioned TPM at startup and adopts it — it must never
   re-provision with a `TPM2_Clear`, which would regenerate the storage seed
   and invalidate the seal written in step 4.
4. Seal the LUKS key **under the Platform KeyStore SRK** (never the SSRK)
   with a PCR policy on the sealed object, plus a non-PCR upgrade seal, and
   write both to the EFI partition. `pcr-banks` records the parent handle
   and its authorization mode (`keystore-platform-policy`) for the unseal
   side to replay.
5. Unlock the LUKS root; copy the installer's contents onto it; apply the
   recovery-key strategy (destroy or escrow).
6. Preserve `installer.luks` if anything in 3–4 failed, and return
   `ErrSealingFallbackUsed` so first boot re-runs next time.

**On every later boot** the initrd records the strategy that actually
unlocked the root — `TPM-PCR`, `Keyfile`, `TPM-NoPCR`, `TPM-Upgrade`, `FIDO2`
or `Password`, matching the strategy's `Name()` — in two places: in the
manager (`Manager.UnlockedWith()`, what `platform-initrd boot` acts on
below) and at `/run/platform/unlock-strategy` (`initrd.UnlockStrategyMarkerPath`,
one line, for the booted system). Until #681 the marker was written only by
`StrategyChain.Execute`, which the boot path does not use; `unlockWithAudit`
writes it now too.

The value is written **only after `Unlock` returns success**, never when a
strategy is merely attempted, and a boot that unlocks by no strategy leaves no
marker at all. Both directions matter because the marker is the evidence #63
uses to decide the TPM-PCR path has been *proven* before wiping
`installer.luks`: a marker naming a strategy that was tried rather than one
that worked would authorise destroying the keyfile on a boot that had just
needed it. Absence is the safe state — no marker, no wipe.

**Seal confirmation (the second half, #63 / #681).** `installer.luks` remains
on the ESP after this phase. The next boot that opens the root **with
`TPM-PCR`** while the container is still there is the proof first boot
deferred, and `platform-initrd boot` acts on it in the same process, before
`switch_root`: it closes the container it mounted — unmount (lazily if
busy), LUKS lock with retries, loop detach — and only when all three
completed destroys the file with `securewipe.File` (`secure-wipe-passes`
from the platform config, NIST single pass by default; each pass fsynced,
the unlink fsynced through the directory, then FITRIM), logging `Seal
confirmed by TPM-PCR unlock` and `installer.luks securely wiped`. A boot that
unlocked by any other strategy preserves the container and says so
(`preserved until a TPM-PCR unlock proves the seal`); a container this
process did not mount is not its to destroy; a container that will not close
is not a file to overwrite (`installer still open, seal confirmation
skipped`); a wipe failure is logged and the boot continues. In every
preserved case the next TPM-PCR boot tries again. Step 4 above also
kills root keyslot 0 (the install-time passphrase) as soon as the sealed key
is written, so from then on only the sealed key (slot 1) and the recovery
passphrase (slot 2, per its strategy) open the root.

### Phase 4 · Seed

The orchestrator resolves the control plane's address — registration report
first, declared static IP second, hostname last — and uploads one device
template per role, then creates one profile per node carrying the **merged**
config (role template → platform globals → per-node overrides → injected node
identity). Profile IDs are captured for Phase 6.

### Phase 5 · Gateways and workers

Same per-node paths as Phase 3, run concurrently for every non-control-plane
node. Before a client node boots, the orchestrator fetches the control plane's
CA bundle (capture-then-verify) and captures its TLS SPKI pin, and stages both
alongside the per-MAC config — so the new node has two independent ways to trust
the control plane at its first enrollment.

### Phase 6 · BMC enrollment (conditional, non-fatal)

Runs only when at least one node sets `bmc_enroll: true`. Each enrollment is a
POST to the control plane using the seeder's already-verified HTTP client;
outcomes land in `BootstrapResult.BMCEnrollments` and, when `backups_dir` is
set, the factory certificate and metadata are written to disk with restrictive
permissions.

### Phase 7 · Health gate, then teardown

Every control-plane node must pass health within the gate timeout. Only then is
the bootstrap container torn down, and a teardown failure is a warning, not a
run failure.

## Trust boundaries

Bootstrap is where trust is *established*, so almost every boundary in the
platform is first drawn here.

1. **Operator workstation → BMC.** The first contact with a BMC is the weakest
   link in the whole flow: BMC certificates are typically self-signed and often
   expired. The `bmc` trust class allows `dane`, `spki`, `ca-file` and
   `tofu`. `tofu` was barred under #83 while it only fetched a CA bundle, which
   a BMC does not serve; go-xkms#139 made it pin the BMC's own certificate on
   first contact, so it is allowed again. First contact is `tofu` where the
   chain lists it, else `bmc_spki_pin`, a fingerprint the operator supplies out
   of band. In a `platformctl bootstrap` run a tofu pin lives in memory for the
   run only. Nothing is persisted, so a later run starts from the same place —
   that is a deliberate limitation, not an oversight.

2. **Operator workstation → deployer host and switch.** Fail-closed SSH host-key
   pinning, no TOFU. An unpinned host is a hard error at client construction.

3. **Orchestrator → control plane (capture-then-verify).** The CA bundle is the
   anchor being fetched, so the served chain is captured during the handshake and
   verified against the downloaded bundle afterwards. A bundle whose own serving
   chain does not validate against it is rejected and never stored. Every later
   connection — seeder, health checker, SPKI pin capture, BMC enrollment — uses
   the resulting pool for ordinary chain verification, which is why the capture
   precedes the control plane's own post-install health probe, and verifies the
   certificate for the control plane's configured TLS name rather than the
   address dialed. The capture itself dials only the operator-declared static
   IPv4 from the bootstrap config, never an address learned from the node's
   unauthenticated `registration.json`. Operations that *establish* trust
   material refuse to run without the pool (`ErrCABundleRequired`); so does the
   seeder — there is no system-pool fallback for a CA that was created minutes
   ago.

4. **Control plane → new node (secret delivery).** Per-MAC values are published
   over **plain HTTP** on the bootstrap container's config endpoint. What is
   published there is deliberately bounded: hostname, the merged installer
   config, the CA bundle (public), and the SPKI pin (public). The provisioning
   network is the trust boundary for that channel — treat anything on it as
   readable by anything else on it, and keep secrets out of role templates that
   reach it.

5. **Node → its own TPM (the seal).** The LUKS key is sealed under a PCR policy
   so the disk unlocks only when the boot chain measures the same. Two seals
   exist for two different purposes: the PCR-bound platform seal is the security
   control; the non-PCR upgrade seal is the recovery path when a kernel upgrade
   changes the measurements. Both are written with restrictive permissions to the
   EFI partition, which is unencrypted — the confidentiality of a TPM-sealed blob
   comes from the TPM, not the filesystem.

6. **The installer container is key material.** `installer.luks` holds the
   plaintext LUKS key and is protected by a well-known password whose only job is
   forensic protection — recovering the file from a discarded SSD should not
   yield a plaintext key. It is **not** access control. Anyone with the file and
   the software has the key, which is why it is securely wiped once sealing has
   succeeded, and why "preserved for retry" is a degraded state to resolve, not
   to live in.

7. **Barrier and seal.** Before the barrier is unsealed the daemon exposes only
   `/healthz`, `/init` and `/unseal`. No gRPC, no QUIC, no MCP, no business REST.
   `/init` is accepted only in the uninitialized state and `/unseal` only in the
   sealed state; both return conflict otherwise. The Shamir path exists so that
   no single operator can unseal alone.

8. **DANE publication is a write to DNS.** Publishing a TLSA record changes what
   every DANE client will accept. The publisher re-signs the zone with DNSSEC on
   every change; a TLSA record in an unsigned or badly-signed zone is not a trust
   anchor, it is a hint.

9. **The recovery key.** First boot either destroys the recovery passphrase's
   keyslot or escrows the plaintext through a tmpfs handoff for the daemon to
   store. Both are explicit choices made by installer configuration. There is no
   third behaviour where a recovery passphrase quietly persists somewhere nobody
   audits.

## What this feature deliberately does not do

- **It does not issue certificates.** The CA does ([`docs/ca/`](../ca/));
  bootstrap publishes, fetches, pins and installs bundles.
- **It does not own the trust strategies.** DANE, Noise and SPKI verification
  live in the stack's trust library and are reached through the SDK. Bootstrap
  owns the *platform-side* publication and the ordered-chain configuration.
- **It does not own the barrier.** `pkg/barrier` is a wrapper over the SDK's
  barrier and ceremony clients. Barrier operations beyond init and unseal belong
  to [`docs/cli/barrier.md`](../cli/barrier.md).
- **It does not build ISOs, serve iPXE, or run the installer.** That is
  [`docs/provisioning/`](../provisioning/). Bootstrap tells those components
  which node is which, and reads back what happened.
- **It does not speak Redfish or IPMI.** It depends on `BoardController`;
  [`docs/bmc/`](../bmc/) implements it.
- **It does not verify attestation evidence.** A node that finishes bootstrap is
  *installed*, not *attested*. Attestation is a separate gate that runs after.
- **It does not expose orchestration remotely.** There is no bootstrap service on
  REST, gRPC, QUIC or MCP, by design as well as by omission: the orchestrator
  holds BMC credentials and drives power. It runs from an operator's CLI. See
  [api.md](api.md) §5.
- **It does not persist BMC trust pins**, so it cannot detect a BMC certificate
  change *between* runs. Publishing BMC TLSA records is the intended answer.
- **It does not prove a seal before wiping the recovery path.** The
  seal-confirmation handshake does not exist yet; until it does, the installer
  container is preserved rather than trusted. See [engineering.md](engineering.md) §7.
