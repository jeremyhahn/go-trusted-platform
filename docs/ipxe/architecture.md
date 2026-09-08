# iPXE Network Boot — Architecture

> **Status: NORMATIVE** · Scope: `pkg/ipxe/`, `cmd/pxeboot` · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> This file replaces the pre-convention `architecture.md`. The accurate
> substance of that document is carried forward; the parts that had drifted
> from the code are corrected and the corrections are listed in
> [engineering.md](engineering.md) §9.

---

## 1. The problem

A machine that has never been provisioned has no operating system, no
credential, and no way to be told what to do. The only thing it can do is
broadcast on the network and execute whatever comes back. **Network boot is
therefore the moment at which an unprovisioned machine is handed its first
executable**, and everything about the design follows from that: the boot server
decides what a bare machine runs before that machine has any way to judge.

The narrower engineering problems on top of that:

- Firmware PXE ROMs are not interchangeable. A legacy-BIOS option ROM and a
  UEFI x64 ROM need different binaries, and handing one the other's image
  produces a silent failure and a DISCOVER loop with no error signal.
- PXE firmware speaks TFTP, which is slow and cannot fetch a kernel from a
  modern mirror. iPXE can, but iPXE does not speak HTTPS.
- Some UEFI firmware, once it sees a `PXEClient` server, tries Boot Server
  Discovery on UDP 4011 and gives up with PXE-E18 rather than downloading the
  boot file it was already offered.
- Every node needs different content — a hostname, a role, an installer config —
  and it is identified only by a MAC address.

## 2. The shape chosen

**One Go process serving three protocols, with a two-stage chainload.**

```
                     ipxe.Server  (pkg/ipxe/server.go)
   ┌────────────────────┬────────────────────┬────────────────────┐
   │   DHCPServer       │   TFTPServer       │   HTTPServer       │
   │   dhcp_server.go   │   tftp_server.go   │   http_server.go   │
   │                    │                    │                    │
   │  UDP 67            │  UDP 69            │  TCP 8080          │
   │  option 60/93/77   │  ipxe.efi          │  /boot.ipxe        │
   │  arch → bootfile   │  ipxe32.efi        │  /menu.ipxe        │
   │  option 43 sub-6   │  undionly.kpxe     │  /boot/{name}.ipxe │
   │  IPAllocator       │  memory cache      │  /boot/device/     │
   └────────────────────┴────────────────────┴────────────────────┘
```

Stage one: the firmware's own PXE ROM gets a DHCP offer whose boot filename is
chosen from the client's **option 93 architecture**, and TFTPs that iPXE binary.
Stage two: iPXE re-DISCOVERs, is recognised by its `iPXE` user class, and is
handed an **HTTP URL** instead of a filename. Everything after that — menu,
per-device script, kernel, initrd — is HTTP on the same server.

`pkg/ipxe` is a **library**. It has no CLI of its own. Three things drive it:
`pkg/bootstrap/container` (behind `cmd/pxeboot`), `pkg/compute/pxe` (the
platform's PXE service), and `pkg/cli/commands/iso` (`platformctl iso test pxe`).

## 3. Rejected alternatives

| Alternative | Why it was rejected |
|---|---|
| **Run dnsmasq / ISC dhcpd + tftpd + nginx** | Four config formats, four failure modes, and no way to answer "what will this MAC boot?" from one place. The per-device script is generated from a manifest in the same process that answers the DHCP request. |
| **One boot filename for every client** | A UEFI binary handed to a legacy-BIOS ROM fails the TFTP load silently and the client loops DISCOVER — the operator sees nothing at all. `DefaultBootFilenameByArch` maps option-93 values `0x0000 → undionly.kpxe`, `0x0006 → ipxe32.efi`, `0x0007`/`0x0009 → ipxe.efi`. `BootFilename` survives as a single-arch fallback for architectures not in the map. |
| **Serve the kernel over TFTP** | TFTP has no windowing worth the name; a 100 MB initramfs over TFTP is minutes. The whole point of the two-stage chainload is to reach HTTP as early as possible. |
| **Let iPXE fetch HTTPS directly** | iPXE builds without HTTPS in the common case. `/proxy/https/{host}/{path}` terminates TLS on the server — with verification mandatory and TLS 1.3 as the floor — and re-serves over plain HTTP on the boot network. |
| **Trust that UEFI firmware will just download the offered bootfile** | It does not. Once option 60 identifies the server as a `PXEClient` server, some firmware enters Boot Server Discovery, gets no answer, and fails with PXE-E18. The DHCP reply therefore sets option 43 sub-option 6 (`PXE_DISCOVERY_CONTROL`) bit 3 — *"download the boot file named in THIS reply"* — with the `0xFF` terminator. Legacy BIOS ROMs are lenient and worked without it, which is why UEFI PXE looked broken while BIOS PXE looked fine. |
| **Bind DHCP with an ordinary UDP socket everywhere** | On a bridged network the reply has to go to a client that does not yet have an address. `dhcp_rawconn_linux.go` provides `ServerRawConn` — an `AF_PACKET` raw socket that builds the Ethernet/IP/UDP framing itself. It is behind `UseRawSocket` and has a `dhcp_rawconn_stub.go` counterpart so the package still builds off Linux. |
| **Respond to every DHCP client always** | That turns the boot server into a rogue DHCP server on any network it is plugged into. The default is to answer only PXE-tagged clients; `DHCPRespondToAll` is opt-in for bootstrap mode, where the server genuinely is the only DHCP server on an isolated segment. |
| **Hard-code the boot menu** | Unknown devices get `GenerateDefaultMenu` built from the configured `BootEntry` list; known devices get `GenerateScript` built from a `DeviceBootInfo` looked up by MAC. Both are generated, neither is a file on disk. |
| **Keep the IP allocator in the DHCP server** | It is the `IPAllocator` interface with two implementations: `InMemoryAllocator` for bootstrap and test, `IPAMAllocator` for a real deployment backed by the platform's IPAM. Injected with `WithIPAllocator`, so the DHCP server never knows which it has. |
| **Give `pkg/ipxe` its own CLI and its own device database** | Device identity, authorisation, quarantine and state belong to provisioning ([`docs/provisioning/`](../provisioning/)). `pkg/ipxe` is handed a `DeviceLookup` callback and answers with a script; it has no opinion about whether the device should be allowed to boot. |

## 4. Component boundaries

| Piece | File | Owner |
|---|---|---|
| Lifecycle orchestrator | `pkg/ipxe/server.go` — `Server`, `NewServer`, `Start`, `Stop`, `WaitForReady`, `IsRunning`, `ServerIP`, `HTTPServer`, `RunWithSignals` | this repo |
| Configuration and validation | `pkg/ipxe/config.go` — `ServerConfig` (aliased `Config`), `BootEntry`, `DefaultServerConfig`, `Validate`, `GetServerIP` | this repo |
| DHCP with PXE options | `pkg/ipxe/dhcp_server.go` — `DHCPServer`, `DHCPConfig`, `DefaultBootFilenameByArch` | this repo |
| Raw-socket DHCP transport | `pkg/ipxe/dhcp_rawconn_linux.go` / `_stub.go` — `ServerRawConn` | this repo |
| IP allocation | `pkg/ipxe/ipam_allocator.go` — `IPAllocator`, `InMemoryAllocator`, `IPAMAllocator` | this repo |
| TFTP firmware server | `pkg/ipxe/tftp_server.go` — `TFTPServer` | this repo |
| HTTP boot, proxy, file and config surface | `pkg/ipxe/http_server.go` — `HTTPServer`, `DeviceLookup`, `SetDeviceLookup` | this repo |
| iPXE script generation | `pkg/ipxe/script_generator.go` — `ScriptGenerator`, `DeviceBootInfo` | this repo |
| ISO boot-file extraction | `pkg/ipxe/iso.go` — `ExtractBootFiles` | this repo |
| Isolated network test harness | `pkg/ipxe/testenv.go` — `TestEnv`, `TestEnvConfig` | this repo |
| **Manifest-driven container server** | `pkg/bootstrap/container` — wraps `ipxe.Server`; the binary is `cmd/pxeboot` | this repo, separate feature |
| **PXE device lifecycle and state machine** | `pkg/compute/pxe/` — `PXEService`, 15 RPCs | this repo — [`docs/provisioning/`](../provisioning/) |
| **Gateway edge PXE mode** | `pkg/sdn/gateway/modes/edge_pxe.go` | this repo — [`docs/gateway/`](../gateway/) |
| **DHCP wire protocol** | `github.com/insomniacslk/dhcp` | **not this repo** |
| **TFTP wire protocol** | `github.com/pin/tftp/v3` | **not this repo** |
| **iPXE firmware binaries** | downloaded from `boot.ipxe.org` | **not this repo** |
| **IPAM pools** | the platform IPAM (`ipam.Allocator`) | this repo, separate feature |
| **What the booted installer then does** | [`docs/installer/`](../installer/) | this repo, separate feature |

**`cmd/pxeboot` does not import `pkg/ipxe` directly.** It builds a
`container.ServerConfig` and calls `container.NewServer`, which is documented in
its own source as *"wraps pkg/ipxe.Server with manifest-based boot script
generation"*. The pre-convention document implied `pxeboot` was a thin wrapper
over `pkg/ipxe`; the manifest layer sits in between.

## 5. Data flow — a bare machine to a running installer

```
 client firmware              DHCPServer           TFTPServer        HTTPServer
      │                            │                    │                │
      │ DISCOVER  (opt 60 PXEClient, opt 93 arch)        │                │
      ├───────────────────────────►│                    │                │
      │                       isPXEClient? ──► allocate via IPAllocator
      │                       bootFilenameForArch(opt 93)
      │ OFFER  yiaddr + siaddr + file=<arch bootfile>    │                │
      │        + opt 60 "PXEClient" + opt 43 sub-6 bit 3 │                │
      │◄───────────────────────────┤                    │                │
      │ RRQ <arch bootfile>                              │                │
      ├──────────────────────────────────────────────────►                │
      │ iPXE binary (memory cache, backed by an on-disk firmware cache)   │
      │◄──────────────────────────────────────────────────┤               │
      │                                                                   │
      │ ── iPXE starts, DISCOVERs again, now with user class "iPXE" ──    │
      ├───────────────────────────►│                                      │
      │ OFFER  bootfile = http://<server>:8080/boot.ipxe                   │
      │◄───────────────────────────┤                                      │
      │ GET /boot.ipxe                                                     │
      ├────────────────────────────────────────────────────────────────────►
      │ chain → /boot/device/<mac>.ipxe   (when a DeviceLookup is wired)   │
      │         else → /menu.ipxe → /boot/{name}.ipxe                      │
      │◄────────────────────────────────────────────────────────────────────
      │ GET /data/vmlinuz  ·  /data/initramfs  ·  /files/*  ·  /proxy/https/…
      ├────────────────────────────────────────────────────────────────────►
      │ kernel + initrd                                                    │
      │◄────────────────────────────────────────────────────────────────────
      │ boot → autoinstall reads platform_* kernel args
      │        GET /config/mac/<mac>/hostname
      │        GET /config/mac/<mac>/installer.yaml
      │        … installs …
      │        PUT /installs/<hostname>/install.log
      v
```

**What crosses a process boundary.** The DHCP, TFTP and HTTP surfaces are all
plain network protocols on the boot segment — none of them is one of the
platform's six transports. `IPAMAllocator` calls out to the platform IPAM.
`DeviceLookup` is a Go callback supplied by whoever embedded the server, which
in the container case resolves against a manifest and in the platform case
against the PXE device store.

**What is persisted.** `InMemoryAllocator` keeps leases in a map and loses them
on restart. `IPAMAllocator` delegates and offers `SyncFromIPAM` to rebuild its
view. Uploaded install logs go to `InstallsDir` (default `/data/installs`) as
`{hostname}/{filename}`. Per-MAC config values go under
`InstallsDir/config/mac/{mac}/{key}`. Firmware is loaded from and cached under
`ServerConfig.FirmwareDir` when set, else `$XDG_CACHE_HOME/go-trusted-platform/firmware/`,
falling back to `/var/cache/go-trusted-platform/firmware/` when the process has
no per-user cache directory. A file missing from that directory is downloaded
from `ServerConfig.FirmwareUpstream` (default `https://boot.ipxe.org`, an
infrastructure decision and therefore configuration) unless
`ServerConfig.FirmwareOffline` is set, in which case a missing `ipxe.efi` is
`ErrFirmwareUnavailable` and the server refuses to start (#590). The bootstrap
deployer container passes the same three fields through
(`container.ServerConfig`). Unit tests always run with a fixture directory and
offline — a unit test never leaves the process.

## 6. Trust boundaries

**This is the feature that decides what an unprovisioned machine executes.**
Six boundaries.

1. **DHCP is unauthenticated, and so is every PXE boot.** A client is
   identified by a MAC address it asserts. Any machine on the segment can claim
   any MAC and receive that MAC's boot script, hostname and `installer.yaml`.
   **The security control is the network segment, not the protocol.** Run the
   boot server on an isolated provisioning VLAN.
2. **The boot server is the machine's first root of trust.** It chooses the
   iPXE binary, the kernel, the initrd and the kernel command line. Whoever
   controls it controls every node that boots from it — including the
   `platform_config=`, `platform_role=`, `platform_hostname=` and
   `bootstrap_strategy=` arguments that decide who the node trusts *afterwards*.
3. **Nothing served over TFTP or HTTP is signature-verified by this
   package.** The iPXE firmware is fetched over HTTPS from `boot.ipxe.org` on
   first use and then cached to disk; **a poisoned cache file is served without
   revalidation**, and there is no signature check on kernel or initrd either.
   The integrity control downstream is UEFI Secure Boot on the installed UKI
   ([`docs/installer/`](../installer/)), not anything here.
4. **`DHCPRespondToAll` makes the process a general-purpose DHCP server.**
   Enabling it on a shared network hands addresses to machines that were not
   asking for anything to do with the platform. Bootstrap mode only.
5. **`/proxy/https/…` is an unrestricted outbound HTTPS relay.** It validates
   only that the scheme is `https`, then fetches. There is **no host
   allowlist**, so anything that can reach TCP 8080 can make the boot server
   fetch an arbitrary HTTPS URL and stream the result back. TLS verification is
   mandatory (TLS 1.3 floor, `ProxyCACertPool` or the system pool), so the
   *fetch* is authenticated — the *relay* is not authorised.
6. **`/config/mac/*` and `/installs/*` carry no authentication at all.**
   `PUT /config/mac/{mac}/{key}` is how the orchestrator stages a node's
   hostname and its whole merged `installer.yaml`; `GET` is how the autoinstall
   script reads it back. Anyone who can reach the port can read another node's
   installer configuration or overwrite it before it boots. Path shape is
   validated (`^mac/([0-9a-f\-]{12,17})/([a-z0-9][a-z0-9._\-]{0,64})$`),
   traversal is blocked, and writes are capped at 256 KiB for config and 16 MiB
   for install logs — but **none of that is authorisation**. Same as boundary 1:
   the segment is the control.

## 7. What this feature deliberately does not do

- **It does not decide whether a machine may boot.** No authorisation, no
  quarantine, no device state. `PXEService` owns that
  ([`docs/provisioning/api.md`](../provisioning/api.md) §2), and the DHCP server
  will happily hand a boot file to a device provisioning has quarantined —
  the enforcement point is the network, not this code.
- **It does not verify what it serves.** §6.3.
- **It does not install anything.** It delivers a kernel and an initrd; the
  installer takes over from there ([`docs/installer/`](../installer/)).
- **It does not build ISOs.** It can *read* one — `ExtractBootFiles` pulls
  kernel, initrd, modloop and kernel args out of an ISO so a PXE test can boot
  the same image a CD would. Building is `pkg/iso`.
- **It does not serve DNS.** `DHCPDNS` advertises a DNS server address; it does
  not run one.
- **It has no CLI surface of its own.** `platformctl` has no `pxe` command
  group. `cmd/pxeboot` is a container entrypoint with flags, not an operator
  CLI; `platformctl iso test pxe` is a test harness. See [cli.md](cli.md).
- **It has no platform API surface of its own.** No REST, gRPC, QUIC or MCP
  route belongs to `pkg/ipxe`. The PXE *control plane* is `PXEService` and is
  documented in [`docs/provisioning/api.md`](../provisioning/api.md); see
  [api.md](api.md) for the row-by-row split.
- **It does not do IPv6.** `DHCPServer` is DHCPv4 (`dhcpv4`, `server4`)
  throughout, and `GetServerIP` returns the first non-loopback **IPv4**
  address.

## 8. Related

- [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md)
- [configuration.md](configuration.md), [testing.md](testing.md),
  [README.md](README.md) — pre-convention documents kept for their worked
  examples. Where they disagree with the five files, the five files win; the
  corrections are in [engineering.md](engineering.md) §9.
- [`docs/provisioning/`](../provisioning/) — device lifecycle, config delivery,
  the `PXEService` transport matrix
- [`docs/installer/`](../installer/) — what the booted kernel does next
- [`docs/bootstrap/config-delivery.md`](../bootstrap/config-delivery.md) — the
  orchestrator side of `/config/mac/*`
- [`docs/daemon/api.md`](../daemon/api.md) — the platform transport model
