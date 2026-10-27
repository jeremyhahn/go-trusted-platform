# iPXE Network Boot — API

> **Status: NORMATIVE** · Scope: `pkg/ipxe/` capabilities on every transport, plus the boot-time wire surface · Last verified: 2026-09-04
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. Two surfaces that are easy to confuse

`pkg/ipxe` **serves** DHCP, TFTP and HTTP. None of those is one of the
platform's six transports. They are boot-time network protocols spoken to
firmware that has no identity and no TLS stack, and they are documented in §3
as a wire surface rather than as an API.

Separately, the platform has a **PXE control plane** — register a device, get it
by MAC, authorize it, quarantine it, retry it, start and stop the service. That
is `PXEService` (15 RPCs, `pkg/api/grpc/proto/pxe.proto`) and it *does* exist on
five transports. **It is owned by provisioning and documented in
[`docs/provisioning/api.md`](../provisioning/api.md) §2.** It is summarised in
§4 here with a pointer, and not duplicated.

So the answer to "what is the iPXE API?" is: **`pkg/ipxe` itself has no platform
API surface.** No REST route, no gRPC service, no QUIC opcode and no MCP tool
belongs to it — grepped 2026-08-18. It is a library with a wire surface.

**The transport model itself is [`docs/daemon/api.md`](../daemon/api.md)** —
the six protocol constants, the QUIC frame and status vocabulary, the category
opcode table, and the platform-wide authorization picture. This file does not
repeat any of it.

---

## 2. `pkg/ipxe` capabilities

`Embedded` here means an in-process Go call. `ServiceRegistry`
(`sdk/go/transport/embedded/adapter.go`) has a `PXE` field, but it carries
`pkg/compute/pxe`'s service — **not** `ipxe.Server` — so there is no embedded
*transport* route to any row below either.

| Capability | Embedded Go call | Unix | REST | gRPC | QUIC | MCP |
|---|---|---|---|---|---|---|
| Construct a boot server | `ipxe.NewServer(*ServerConfig, logger)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Start / stop all services | `(*Server).Start(ctx)`, `.Stop()`, `.RunWithSignals(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Wait for readiness | `(*Server).WaitForReady(timeout)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Query server state | `(*Server).IsRunning()`, `.ServerIP()`, `.HTTPServer()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Default and validate configuration | `ipxe.DefaultServerConfig()`, `ipxe.DefaultConfig()`, `(*ServerConfig).Validate()`, `(*BootEntry).Validate()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Resolve the server IP | `(*ServerConfig).GetServerIP()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Run DHCP standalone | `ipxe.NewDHCPServer(*DHCPConfig, logger, opts...)` → `Start(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Choose a boot file by client architecture | `ipxe.DefaultBootFilenameByArch()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Substitute the DHCP socket | `ipxe.WithPacketConnFactory(f)`, `(*DHCPServer).SetConnFactory(f)`, `ipxe.DefaultPacketConnFactory` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Raw-socket DHCP transport | `ipxe.NewServerRawConn(iface, serverIP, port)` (Linux; stubbed elsewhere) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Allocate / release / renew an IP | `IPAllocator.Allocate` / `.Release` / `.Renew` / `.GetLease` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| In-memory lease table | `ipxe.NewInMemoryAllocator(start, end, leaseTime)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| IPAM-backed leases | `ipxe.NewIPAMAllocator(alloc, poolID, leaseTime)`; `.PoolID()`, `.LeaseCount()`, `.SyncFromIPAM(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Inject an allocator | `ipxe.WithIPAllocator(a)`, `(*DHCPServer).SetAllocator(a)`, `.GetAllocator()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Serve iPXE firmware | `ipxe.NewTFTPServer(cfg, serverIP, logger)` → `Start(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Serve boot scripts and files | `ipxe.NewHTTPServer(cfg, logger)` → `Start(ctx)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Resolve a MAC to boot info | `(*HTTPServer).SetDeviceLookup(DeviceLookup, *ScriptGenerator)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate a per-device iPXE script | `ipxe.NewScriptGenerator(addr, logger)` → `GenerateScript(*DeviceBootInfo)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Generate the fallback menu | `(*ScriptGenerator).GenerateDefaultMenu([]BootEntry)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Extract boot files from an ISO | `ipxe.ExtractBootFiles(isoPath)` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |
| Build an isolated test network | `ipxe.NewTestEnv(*TestEnvConfig, logger)`; `Setup`, `Start`, `Stop`, `Cleanup`, `TapName`, `ServerIP`, `ServerConfig`, `Network`; `ipxe.DefaultTestEnvConfig()` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` |

**One of these is not usable from outside the package.** `IPAllocator.GetLease`
returns the unexported `*lease`, so no external type can satisfy the interface
even though `WithIPAllocator` accepts it. See
[engineering.md](engineering.md) §2.

---

## 3. The boot-time wire surface

**Not one of the six transports.** These are the protocols the server speaks to
firmware. No authentication on any of them; see
[architecture.md](architecture.md) §6.

### 3.1 DHCP — UDP 67

| Direction | Content |
|---|---|
| In | `DISCOVER` / `REQUEST`. Client type is read from option 60 (`PXEClient` prefix) or the presence of option 93; iPXE is read from option 77 user class `iPXE` |
| Out | `yiaddr` from the `IPAllocator`; `siaddr` = server IP; `file` = the arch-selected boot filename, or the iPXE script URL for an iPXE client; option 1 subnet mask; option 3 router when `DHCPGateway` set; option 6 with every `DHCPDNS` server, in order, when the list is non-empty; option 51 lease time; **option 60 `PXEClient`**; **option 43 = `{0x06, 0x01, 0x08, 0xFF}`** |

Option-93 to boot filename:

| Option 93 | Filename |
|---|---|
| `0x0000` legacy BIOS x86 | `undionly.kpxe` |
| `0x0006` UEFI IA32 | `ipxe32.efi` |
| `0x0007` UEFI x64 | `ipxe.efi` |
| `0x0009` UEFI byte code | `ipxe.efi` |
| anything else | `ServerConfig.BootFilename` (default `ipxe.efi`) |

Non-PXE clients are ignored unless `DHCPRespondToAll` is set. A packet whose
`chaddr` is empty or all zeros is ignored whatever its type: leases are keyed
on the hardware address.

### 3.2 TFTP — UDP 69

Read-only. Three filenames are served from memory: `ipxe.efi` (required at
startup), `ipxe32.efi` and `undionly.kpxe` (optional). Any other filename gets
`ErrFirmwareNotFound`. Transfer timeout 5 s.

### 3.3 HTTP — TCP 8080

`ReadTimeout` and `WriteTimeout` are 30 s; every request is logged with method,
path, status, duration and remote address.

The port is `ServerConfig.HTTPPort`. Under the bootstrap container it is set
from `pxeboot --http-port`, which the deployer drives from
`deployer.bootstrap_http_port` ([`docs/bootstrap/engineering.md`](../bootstrap/engineering.md) §5).

**The bootstrap container serves `/boot/device/` twice, identically.** It wires
its manifest into this server with `SetDeviceLookup`, so the route below is
what `/boot.ipxe` chains; and it runs its own `http.Server` on
`ServerConfig.DeviceScriptPort` — `--device-script-port`, defaulting to
`--http-port` + 1 — which the deploy gate probes as its readiness signal. A
known MAC gets the same script from both (one lookup, one generator); an
unknown MAC gets a 404 here and, on the second listener, a script that chains
`/boot.ipxe`. That listener is where a port conflict on the deployer kills
pxeboot, which is why the port is configurable rather than derived-only. It
also serves `GET /boot/uki/{mac}.efi`, an installed `diskless-nbd` node's UKI
read from its NBD export, which that node's device script boots
([bootstrap engineering](../bootstrap/engineering.md#the-diskless-nbd-runtime-path));
this server has no such route.

| Method | Path | Purpose | Registered when |
|---|---|---|---|
| GET | `/boot.ipxe` | Stage-two entry script | always |
| GET | `/menu.ipxe` | Boot menu built from `BootEntries` | always |
| GET | `/boot/device/{mac}.ipxe` | Per-device script from `DeviceLookup` + `ScriptGenerator` | only when **both** are set before `Start` |
| GET | `/boot/{name}.ipxe` | Per-boot-entry script | always — registered **after** `/boot/device/` so it does not shadow it |
| GET | `/health` | Liveness | always |
| GET | `/static/*` | Static files | always |
| GET | `/files/*` | Files under `LocalFilesDir` | `LocalFilesDir != ""` |
| GET | `/data/*` | Files under `DataDir` — kernel, initramfs, ISOs, and the Raspberry Pi's signed HTTP boot files (`/data/http-boot/{boot.img,boot.sig}`, the EEPROM's `HTTP_PATH=data/http-boot`) | `DataDir != ""` |
| GET | `/media/status` | Open files under `DataDir` with read offsets and opener process names — the orchestrator's evidence that a virtual-media host is reading the ISO | always (503 if `DataDir == ""`, 405 on any other method) |
| GET | `/proxy/https/{host}/{path}` | HTTPS→HTTP relay for iPXE | always |
| PUT | `/installs/{hostname}/{filename}` | Install-log upload | always |
| GET | `/installs/` · `/installs/{hostname}/` | HTML index | always |
| GET | `/installs/{hostname}/{filename}` | Serve a stored log as `text/plain` | always |
| PUT | `/config/mac/{mac}/{key}` | Orchestrator stages a per-node value | always (503 if `InstallsDir == ""`) |
| GET | `/config/mac/{mac}/{key}` | Node reads the staged value | always (503 if `InstallsDir == ""`) |

**The two MAC formats are not the same, and this is the single easiest thing to
get wrong here.**

| Route | Accepted form | Handling |
|---|---|---|
| `/boot/device/{mac}.ipxe` | colons **or** dashes, any case | lowercased and dashes rewritten to colons, then passed to `DeviceLookup` — so the lookup callback always sees `aa:bb:cc:dd:ee:ff` |
| `/config/mac/{mac}/{key}` | **lowercase, dash-separated only** | matched against `^mac/([0-9a-f\-]{12,17})/…$`; a colon-separated or uppercase MAC is a 400 |

`GET /health` returns `{"status":"healthy"}` as `application/json`.

`GET /media/status` returns the media watcher's cumulative record:

```json
{"data_dir":"/data","since":"…","sampled_at":"…","interval":250000000,
 "files":[{"path":"/data/x.iso","opens":1,"max_pos":1048576,"open_samples":812,
           "first_seen":"…","last_seen":"…",
           "openers":[{"name":"smbd","client":"10.4.2.103","opens":1,"open_samples":812,"open_events":1,
                       "pos_changes":640,"max_pos":1048576,
                       "first_seen":"…","last_seen":"…","last_activity":"…"}]}]}
```

The watcher starts with the server when `DataDir` is set and scans
`/proc/*/fd` every 250 ms for descriptors that resolve under `DataDir`
(pxeboot's own excluded), reading each one's `fdinfo` `pos:` and the holder's
`/proc/<pid>/comm`; pxeboot and smbd share the container's PID namespace, so no
`smbstatus` is involved. The record is cumulative since `since`, per file and per holding process
name: `open_samples` counts the samples in which the file was open,
`first_seen`/`last_seen` bracket them, `max_pos` is the furthest offset ever
seen, `opens` the descriptors open at the last sample (0 once closed — the
history stays). Each `openers` entry carries the same for one process — keyed by process
name **and** `client`, the address in smbd's per-connection process title:
Debian's `smbd: client [ip]` in cmdline, or Alpine/musl's `smbd[ip]` carried
in the 15-byte `comm` (a title cut short of its closing bracket is captured
as an IP prefix and reported with `"client_truncated":true`), so two BMCs
reading the same ISO are two entries — plus
`open_events` (samples in which it was found holding the file after not
holding it at the previous sample — a fresh open) and `pos_changes` (samples in
which its summed descriptor offsets moved — data flowing), with
`last_activity` the last sample that counted either. A read that began and
ended between two client polls is therefore still on record, and an idle
descriptor held across a power cycle is not activity. The BMC only reads the
ISO while the host firmware reads the emulated CD, so `smbd` activity
(`open_events + pos_changes`) rising past a baseline taken while the chassis is
confirmed off, with a `last_activity` inside the attempt, means the host booted
the media; the orchestrator looks at the `smbd` entries for the node's own BMC
address alone (every `smbd` entry only when none carries a `client`, and an
entry with no name never; a truncated `client` is matched as a prefix), so an
operator's checksum or backup reading the ISO is not mistaken for this host
booting, and neither is another node's BMC — except where a truncated prefix
covers both addresses (BMCs on one /24 management subnet share it), in which
case same-subnet neighbours can vouch for each other. **This evidence is advisory** (go-trusted-platform #126,
measured 2026-08-30): the ATEN BMC's ISO reads never appear as held smbd
descriptors during a real install — only transient mount-time opens do —
so the orchestrator logs a never-observed window and falls through to the
install-log wait instead of failing the attempt. Two limits of the
attribution are worth knowing: a Samba build
that does not retitle its workers leaves every `client` empty, and the record
then degrades to counting all `smbd` activity (concurrent nodes can again
vouch for each other; check the worker title on the deployer with
`cat /proc/$(pgrep -n smbd)/comm` and `.../cmdline`); and the address is
matched against the node's `bmc_address`, so a BMC whose SMB traffic leaves
from a different address than it is managed on is never attributed — the fix
is a per-node override the config does not carry yet. `files` is `[]` when nothing was ever open. The route
answers 503 until the watcher runs (no `DataDir`), until its first successful
scan, and whenever its latest successful scan is older than four intervals —
a stale record is not evidence, and the probe treats 503 as "ask again".

**Other path constraints, enforced:**

- `{mac}` on `/config/mac/…` matches `[0-9a-f\-]{12,17}`.
- `{key}` matches `[a-z0-9][a-z0-9._\-]{0,64}`.
- `..` anywhere in a `/config/` or `/installs/` path is a 400.
- Config values are capped at 256 KiB (`maxConfigValueBytes`); install-log
  uploads at 16 MiB (`maxInstallLogUploadBytes`).
- Uploads are written as `.partial` and atomically renamed, so a half-uploaded
  log never appears in the index.
- `/proxy/` accepts `https` only; anything else is a 400. TLS verification is
  mandatory, TLS 1.3 is the floor, and the root pool is `ProxyCACertPool` or the
  system pool. **There is no host allowlist.**

**Keys in use today:** `hostname` and `installer.yaml`. The server stores plain
bytes and interprets nothing — the consumer decides the format.

### 3.4 Status codes

| Code | When |
|---|---|
| 200 | Success |
| 400 | Malformed `/config` or `/installs` path, bad MAC or key shape, `..`, non-HTTPS proxy scheme, oversized body |
| 404 | Unknown boot entry, unknown file, unknown stored value |
| 405 | Method not allowed on `/config`, `/installs` or `/media/status` |
| 500 | Directory creation or write failure |
| 502 | Proxy fetch failed |
| 503 | `/config/*` with no `InstallsDir` configured; `/media/status` with no `DataDir`, before its first successful scan, or with a record older than four sampling intervals |

The QUIC status vocabulary in [`docs/daemon/api.md`](../daemon/api.md) §4 does
not apply here — nothing on this surface speaks QUIC.

---

## 4. The PXE control plane — owned elsewhere

Fifteen capabilities on five transports, documented row by row in
[`docs/provisioning/api.md`](../provisioning/api.md) §2. Summarised so a reader
who arrived here can find them:

| Capability group | REST base | gRPC | QUIC | MCP |
|---|---|---|---|---|
| Device lifecycle — register, list, get, get-by-MAC, remove, update state, set enrolled | `/api/v1/pxe/devices` | `PXEService` | `0xEC`–`0xEF`, remove `0xFF`; get-by-MAC and set-enrolled `0xCF` subs `0x30`, `0x31` | `pxe_*` |
| **Authorize / quarantine / retry** | `/api/v1/pxe/devices/{id}/…` | `PXEService` | `0xFC`, `0xFD`, `0xFE` | `pxe_authorize_device`, `pxe_quarantine_device`, `pxe_retry_device` |
| Events | `GET /api/v1/pxe/devices/{id}/events` | `GetEvents` | `0xCF` sub `0x32` | `pxe_get_device_events` |
| Service status / start / stop | `/api/v1/pxe/status`, `/start`, `/stop` | `GetStatus`, `StartService`, `StopService` | `0xCF` subs `0x33`, `0x34`, `0x35` | `pxe_service_status`, `pxe_start_service`, `pxe_stop_service` |
| Install-complete webhook | `POST /api/v1/pxe/webhook/complete` | `WebhookComplete` | `0xCF` sub `0x36` | `pxe_webhook_complete` |
| Gateway-side provisioning — register, state, install complete | `/api/v1/provisioning/devices/{mac}/…` ([provisioning api.md](../provisioning/api.md) §4) | `ProvisioningGateway` (4 RPCs) | — | — |

**The install-complete webhook route exists only when the operator sets
`pxe.ServiceConfig.WebhookEnabled`** (default `false`). Disabled, the path is
not registered and answers 404 like any unknown path. Enabled, the node
**authenticates by its installer certificate over mTLS** (#238): the device is
the one whose `install_certificate_sha256` is the SHA-256 of the leaf of the
verified client chain, and a MAC in the request body must match it. The
operator binds that fingerprint when the device enters installing (`UpdateState`
with `install_certificate_sha256`); a serial is not used, because it is unique
only per issuer. No verified client certificate is 401; a certificate no device
carries, or a mismatched MAC, is 403. Transports with no peer certificate —
Unix, MCP stdio, embedded — refuse the call.

**The `REST base` column is a locator, not the contract.** It gives the prefix a
route hangs under; it does not give the route. The normative per-route path
**and HTTP method** for all fifteen are the first column of
[`docs/provisioning/api.md`](../provisioning/api.md) §2, which is `Status:
NORMATIVE` — conflicts with it are defects. Two of the fifteen matter here
because a client read this summary and guessed the rest:

| Capability | Normative route | Guessed instead |
|---|---|---|
| Get device by MAC | `GET /api/v1/pxe/devices/mac/{mac}` | `GET …/devices/by-mac/{mac}` |
| Update state | `PUT /api/v1/pxe/devices/{id}/state` | `POST …/devices/{id}/state` |

The second is a **method** mismatch on a path that matches exactly. Routes here
are registered on a `mux` subrouter, which answers a `POST` to a `PUT`-only
route with **404, not 405** — the opposite of the wire surface in §3, whose
hand-rolled method checks do return 405. So on the control plane a wrong verb
and an unimplemented route are indistinguishable from the client, and the
client cannot tell it guessed. Record the method beside the path or this
recurs.

The SDK's own REST transport guessed too, until #452. It sent `UpdateState`,
`Authorize` and `Quarantine` to `…/devices/state`, `…/devices/authorize` and
`…/devices/quarantine` with the device in the body, and no router serves those
paths. It now claims the normative item routes. The device id travels only in
the path (the templated rows in `sdk/go/transport/rest/adapter.go`), and a
request without one is refused with `InvalidArgument` before it is sent.

**The SDK REST transport carries all fifteen (#975).** Until then it mapped
eight. `StartService`, `StopService`, `GetDeviceByMAC`, `RemoveDevice`,
`SetDeviceEnrolled`, `Retry` and `GetEvents` had no route, so the SDK failed
them before sending anything. The MAC and the device id travel only in the
path. `ListDevices` sends its filter as the query parameters
[`docs/provisioning/api.md`](../provisioning/api.md) §2 defines: `state` as the
enum name, then `mac_address`, `vlan`, `limit` and `offset`. Unset fields are
left out. `pkg/api/daemon/pxe_rest_sdk_test.go` drives all fifteen through the
SDK against the PXE router. It requires the same reply and service call as
gRPC, and the same refusals.

**QUIC carries all fifteen (#704).** Eight methods have a direct opcode in
`sdk/go/wire/quicwire/protocol.go` (`0xEC`–`0xEF`, `0xFC`–`0xFF`); the other
seven ride the provisioning category `0xCF` as subs `0x30`–`0x36`
(`sdk/go/wire/quicwire/pxe_opcodes.go`). The daemon dispatches every one through
a map to the gRPC servicer (`pkg/api/daemon/quic_pxe.go`), and the SDK QUIC
adapter maps all fifteen (`sdk/go/transport/quic/aab_pxe.go`). The per-method
opcode is in [`docs/provisioning/api.md`](../provisioning/api.md) §2.

---

## 5. Authorization

**None on the wire surface.** No `scp` claim gates DHCP, TFTP or any HTTP route
in §3. A client is identified by a MAC address it asserts, and
`/config/mac/{mac}/{key}` will hand any caller any node's staged
`installer.yaml`. The control is the network segment; see
[architecture.md](architecture.md) §6.

**The control plane is scoped on gRPC.** Both catalogs are default-deny
([`docs/auth/architecture.md`](../auth/architecture.md)), and every `PXEService`
RPC is in the gRPC scope catalog (`pkg/api/grpc/method_permissions.go`):

| Permission | RPCs |
|---|---|
| `pxe:read` | `GetDevice`, `GetDeviceByMAC`, `GetEvents`, `GetStatus`, `ListDevices` |
| `pxe:write` | `Authorize`, `Quarantine`, `RegisterDevice`, `Retry`, `SetDeviceEnrolled`, `StartService`, `StopService`, `UpdateState`, `WebhookComplete` |
| `pxe:delete` | `RemoveDevice` |

Authorizing or quarantining a PXE device therefore needs `pxe:write`.

**QUIC and MCP take the same scopes (#704).** Each QUIC opcode and `0xCF` sub
carries the scope of its RPC (`pkg/api/quic/opcode_permissions.go`), and each of
the fifteen `pxe_*` MCP tools is classified with it (`pkg/api/mcp/pxe_tools.go`);
a caller without the scope is refused before the service is reached.

**REST takes the same scopes (#452).** Behind the platform-token middleware each
operator route takes, on top of the admin role gate, the scope its RPC takes on
gRPC; a token without it gets `403`. The route table names the RPC and reads the
scope from the gRPC catalog (`pkg/webservice/v1/rest/pxe/router.go`), so the two
cannot drift. Under the legacy JWT handler, which carries roles and no scopes,
the role gate alone applies.

| Route | RPC | Scope |
|---|---|---|
| `GET /api/v1/pxe/status` | `GetStatus` | `pxe:read` |
| `POST /api/v1/pxe/start` | `StartService` | `pxe:write` |
| `POST /api/v1/pxe/stop` | `StopService` | `pxe:write` |
| `GET /api/v1/pxe/devices` | `ListDevices` | `pxe:read` |
| `POST /api/v1/pxe/devices` | `RegisterDevice` | `pxe:write` |
| `GET /api/v1/pxe/devices/mac/{mac}` | `GetDeviceByMAC` | `pxe:read` |
| `GET /api/v1/pxe/devices/{id}` | `GetDevice` | `pxe:read` |
| `DELETE /api/v1/pxe/devices/{id}` | `RemoveDevice` | `pxe:delete` |
| `PUT /api/v1/pxe/devices/{id}/state` | `UpdateState` | `pxe:write` |
| `POST /api/v1/pxe/devices/{id}/enrolled` | `SetDeviceEnrolled` | `pxe:write` |
| `POST /api/v1/pxe/devices/{id}/authorize` | `Authorize` | `pxe:write` |
| `POST /api/v1/pxe/devices/{id}/quarantine` | `Quarantine` | `pxe:write` |
| `POST /api/v1/pxe/devices/{id}/retry` | `Retry` | `pxe:write` |
| `GET /api/v1/pxe/devices/{id}/events` | `GetEvents` | `pxe:read` |

`POST /api/v1/pxe/webhook/complete` takes neither the admin gate nor a scope:
its caller is a booting node, authenticated by its mTLS device certificate
rather than an operator credential (#238). [`docs/provisioning/api.md`](../provisioning/api.md) §6
covers the provisioning half of the control plane.

---

## 6. Versioning

Nothing here is versioned by the platform. The compatibility contracts are:

- **DHCP option 93 architecture values** — fixed by RFC 4578, not by us.
- **The boot-file names** `ipxe.efi`, `ipxe32.efi`, `undionly.kpxe` — must match
  what `TFTPServer.loadFirmware` populates and what
  `DefaultBootFilenameByArch` hands out. Changing one without the other
  produces a silent DISCOVER loop.
- **The HTTP path shapes** in §3.3 — `autoinstall.sh` and the bootstrap
  orchestrator both hard-code them.
- **The kernel-argument names** `platform_config=`, `platform_role=`,
  `platform_hostname=`, `bootstrap_strategy=`, `platform_apk_mirror=`,
  `platform_debug=`, `platform_debug_sink=` — emitted by `GenerateScript` and
  by `pkg/iso`, consumed by `autoinstall.sh` and `pkg/app`.

Nothing is deprecated.
