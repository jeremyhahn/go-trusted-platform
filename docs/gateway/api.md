# Edge Gateway — API

> **Status: NORMATIVE** · Scope: gateway and proxy routes on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column.
`ServiceRegistry.Gateway` and `ServiceRegistry.Proxy` carry both services
in-process.

Two gRPC services: `GatewayService` (29 RPCs, `gateway.proto`) and
`ProxyService` (14 RPCs, `proxy.proto`).

**MCP is served over stdio / HTTPS on port 9445.** The tool definitions are in
`pkg/api/mcp/gateway_tools.go`, with the LB and perf tools registered alongside.

**QUIC reaches both through the gateway category opcode `0x2F`.** Sub-opcodes
`0x20`–`0x2D` under that category are routed to the **proxy** handler; the rest
go to the gateway handler (`pkg/api/daemon/quic_service.go`). IPAM additionally
has its own category opcode `0x3F`. Sub-opcode values collide with top-level
opcodes by design — `0x01` under `0x2F` is `OpGatewayStatus`, while `0x01` at
top level is `OpLiveness`.

---

## 2. Gateway status and mode

REST base path `/api/v1/gateway` (`pkg/webservice/v1/rest/gateway/router.go`).

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| Gateway status | `GET /api/v1/gateway/status` | `GetGatewayStatus` | `OpGatewayStatus` (`0x01`) | `gateway_status` | ✅ |
| Set gateway mode | `POST /api/v1/gateway/mode` | `SetGatewayMode` | `OpGatewaySetMode` (`0x02`) | `gateway_mode_set` | ✅ |
| Gateway telemetry snapshot | `GET /api/v1/gateway/state/{id}` | `GetGatewaySnapshot` | `OpGatewaySnapshot` (`0x15`) | `gateway_snapshot` | ✅ |
| List reported snapshots | `GET /api/v1/gateway/state` | `ListGatewaySnapshots` | `OpGatewayListSnapshots` (`0x16`) | `gateway_snapshots` | ✅ |
| Get admitted overlay VTEP | `GET /api/v1/sdn/gateway/overlay/vteps/{vtep}?gateway_id=<id>` | `GetGatewayAdmittedVTEP` | `OpGatewayAdmittedVTEP` (`0x17`) | `gateway_admitted_vtep` | ✅ |
| List admitted overlay VTEPs | `GET /api/v1/sdn/gateway/overlay/vteps?gateway_id=<id>` | `ListGatewayAdmittedVTEPs` | `OpGatewayListAdmittedVTEPs` (`0x18`) | `gateway_admitted_vteps` | ✅ |

**The snapshot is served from the telemetry the control plane holds** (§8),
which is why its REST form is the `state` route rather than a second path:
one document, one cache, five transports. On a node that runs its own
gateway, `GetGatewaySnapshot` with an empty `gateway_id` returns that
gateway's live state instead. A `gateway_id` that has never reported is
`NotFound` — never an empty snapshot, which would read as a gateway running
nothing. The document's sections and their provenance are in
[`engineering.md`](engineering.md) §8; the CLI form is
`platformctl sdn gateway snapshot [--gateway-id <id> | --all]`.

The overlay section of the snapshot includes the local VTEP, underlay bridge,
OpenFlow table ids, admitted VTEPs, and the neighbor-discovery counters the
gatewayd overlay handler maintains: punted, answered, meter-dropped,
queue-dropped, and fell-through. The admitted-VTEP read/list verbs are backed
by the same service layer and are exposed on REST, gRPC, QUIC, MCP, Unix and
the SDK/CLI; they return `NotFound` for an address that is not currently
admitted, and `Unavailable` (REST 503) on a gateway with no overlay section.
The Go SDK reaches them on every transport: REST uses the two `GET` routes
above (daemon REST stack only), QUIC translates to and from the
`Gateway*AdmittedVTEP*` wire structs (whose field names differ from the pb
messages, with `verdict_at` as Unix seconds), and REST and MCP wrap the bare
single-VTEP record into `GetGatewayAdmittedVTEPResponse.vtep`.

**Every transport answers status and mode from the one gateway gRPC service
(#65).** QUIC, MCP and the `/api/v1/sdn/gateway/{status,mode}` REST routes
bind to it in `pkg/api/daemon/gateway_status_bindings.go`; gRPC, Unix and the
embedded SDK call it directly, and `/api/v1/gateway/*` proxies gRPC. The
service reads the gateway that runs in the same process. `platformd` runs
none (`gatewayd` constructs it), so on a live control plane both verbs answer
"not configured" everywhere: `Unavailable` on gRPC and Unix, 503 on REST,
`StatusUnavailable` on QUIC, and the service error from MCP.

The mode is a bitmask: overlay `1`, edge `2`, transit `4`. Every transport
refuses an empty set or an undefined bit before it asks the gateway:
`InvalidArgument` on gRPC and Unix, 400 on REST, `StatusInvalidArgument` on
QUIC.
MCP's `gateway_mode_set` takes names (`overlay`, `edge`, `transit`) and
refuses any other name; its result spells the active modes out beside the
bitmask.

**`SetGatewayMode` is the deprecated compatibility surface.** `GatewayMode`
carries a deprecation notice in `pkg/sdn/gateway/compat.go` and maps only three
of the service sections. It is documented here because it exists and is
callable, not because it is the way to configure a gateway — see
[architecture.md](architecture.md).

---

## 3. BGP

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| BGP status | `GET /api/v1/gateway/bgp/status` | `GetBGPStatus` | `OpGatewayBGPStatus` (`0x03`) | `gateway_bgp_status` | ✅ |
| List peers | `GET /api/v1/gateway/bgp/peers` | `ListBGPPeers` | `OpGatewayBGPPeers` (`0x04`) | `gateway_bgp_peers` | ✅ |
| List announced prefixes | `GET /api/v1/gateway/bgp/prefixes` | `ListAnnouncedPrefixes` | `OpGatewayListPrefixes` (`0x07`) | `gateway_bgp_prefixes` | ✅ |
| Announce prefix | `POST /api/v1/gateway/bgp/prefixes` | `AnnouncePrefix` | `OpGatewayAnnouncePrefix` (`0x05`) | `gateway_bgp_announce` | ✅ |
| Withdraw prefix | `DELETE /api/v1/gateway/bgp/prefixes` | `WithdrawPrefix` | `OpGatewayWithdrawPrefix` (`0x06`) | `gateway_bgp_withdraw` | ✅ |

> **Production status: routed, not backed.** The BGP speaker runs in
> `gatewayd`; `platformd` never hands one to the gateway service
> (`GatewayService.SetBGPSpeaker` has no production caller). gRPC, Unix,
> REST, QUIC and the embedded SDK therefore answer "not configured", and the
> MCP `gateway_bgp_*` tools answer "not implemented". Backing them needs the
> same control-plane link to gatewayd-resident services as §5a.

Announce and withdraw share
the `/bgp/prefixes` path and are distinguished by method; the prefix travels in
the body, which is why withdraw is a `DELETE` with a payload rather than a path
parameter.

---

## 4. IPAM

REST carries the full pool CRUD under `/api/v1/sdn/gateway/ipam`
(`pkg/webservice/v1/rest/gateway/ipam.go`, the WebUI's Networking → IPAM
contract — see [`docs/sdn/ipam/`](../sdn/ipam/)), plus a reduced
read-oriented set under `/api/v1/gateway/ipam`; gRPC and MCP carry full pool
CRUD. QUIC has both the gateway-category sub-opcodes and a dedicated **IPAM
category opcode `0x3F`**.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| List pools | `GET /api/v1/sdn/gateway/ipam/pools` (`?zone=`); also `GET /api/v1/gateway/ipam/pools` | `ListIPAMPools` | `OpGatewayListIPAMPools` (`0x08`) | `gateway_ipam_pools` | ✅ |
| Create pool | `POST /api/v1/sdn/gateway/ipam/pools` | `CreateIPAMPool` | `OpGatewayCreateIPAMPool` (`0x0C`) | `gateway_ipam_pool_create` | ✅ |
| Get pool | `GET /api/v1/sdn/gateway/ipam/pools/{id}` | `GetIPAMPool` | `OpGatewayGetIPAMPool` (`0x0E`) | `gateway_ipam_pool_get` | ✅ |
| Update pool | `PUT /api/v1/sdn/gateway/ipam/pools/{id}` | `UpdateIPAMPool` | `OpGatewayUpdateIPAMPool` (`0x0F`) | `gateway_ipam_pool_update` | ✅ |
| Delete pool | `DELETE /api/v1/sdn/gateway/ipam/pools/{id}` | `DeleteIPAMPool` | `OpGatewayDeleteIPAMPool` (`0x0D`) | `gateway_ipam_pool_delete` | ✅ |
| List allocations | `GET /api/v1/sdn/gateway/ipam/allocations` (`?pool_id=`); also `GET /api/v1/gateway/ipam/allocations` | `ListAllocations` | `OpGatewayListAllocations` (`0x0B`) | `gateway_ipam_allocations` | ✅ |
| Allocate IP | `POST /api/v1/sdn/gateway/ipam/allocations`; also `POST /api/v1/gateway/ipam/allocations` | `AllocateIP` | `OpGatewayAllocateIP` (`0x09`) | `gateway_ipam_allocate` | ✅ |
| Release IP | `DELETE /api/v1/sdn/gateway/ipam/allocations/{ip}`; also `DELETE /api/v1/gateway/ipam/allocations` | `ReleaseIP` | `OpGatewayReleaseIP` (`0x0A`) | `gateway_ipam_release` | ✅ |

The `/sdn/gateway/ipam` surface wraps the documented snake_case objects in
the standard platform response envelope (`{code, error, success, payload}`);
the reduced `/gateway/ipam` surface keeps its protojson payloads.

**Every IPAM verb is served from the allocator `platformd` owns**, on every
transport; the MCP tools live in `pkg/api/daemon/gateway_ipam_tools.go`.
A pool update changes only what it names on REST, QUIC and MCP. The gRPC
`UpdateIPAMPool` replaces `zone` and `description` outright, and either
duration whenever it is not negative: send `-1` to keep a duration, and the
current zone and description to keep those. `platformctl sdn ipam pool
update` does that for every flag it was not given.

**The Go SDK client carries status, mode and every IPAM verb on every
transport.** Over REST it uses the full `/api/v1/sdn/gateway/ipam` surface
(`sdk/go/transport/rest/gateway_ipam.go`). Over QUIC it uses the `0x2F`
sub-opcodes (`sdk/go/transport/quic/gateway_status_ipam.go`), and over MCP
the `gateway_*` tools (`sdk/go/transport/mcp/gateway_status_ipam.go`). gRPC,
Unix and embedded call the service directly. The client maps the gRPC
`UpdateIPAMPool` onto the REST, QUIC and MCP updates, which change only what
they name:

- A `-1` duration is omitted, and a positive one is sent.
- `update_window` sends the whole window, so an empty bound or reserved list
  clears it, as on gRPC.

Before anything is sent, the client refuses with `InvalidArgument` what a
transport cannot carry:

- On REST, QUIC and MCP: a zero duration, because those updates keep a
  duration they are not given.
- On MCP only:
  - an inactivity timeout;
  - a caller-chosen pool ID on create;
  - a duration that is not a whole number of seconds.

An empty zone or description is kept on those three transports, not cleared.

---

## 5. Load balancer

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| LB status | `GET /api/v1/sdn/gateway/lb/status` | `GetLBStatus` | `OpGatewayLBStatus` (`0x35`) | `gateway_lb_status` | ✅ |
| Add VIP | `POST /api/v1/sdn/gateway/lb/vips` | `AddVIP` | `OpGatewayLBAddVIP` (`0x30`) | `gateway_lb_vip_add` | ✅ |
| Get VIP | `GET /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}` | `GetVIP` | `OpGatewayLBGetVIP` (`0x32`) | `gateway_lb_vip_get` | ✅ |
| List VIPs | `GET /api/v1/sdn/gateway/lb/vips` | `ListVIPs` | `OpGatewayLBListVIPs` (`0x33`) | `gateway_lb_vip_list` | ✅ |
| Remove VIP | `DELETE /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}` | `RemoveVIP` | `OpGatewayLBRemoveVIP` (`0x31`) | `gateway_lb_vip_remove` | ✅ |
| Set VIP backends | `PUT /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends` | `SetVIPBackends` | `OpGatewayLBSetVIPBackends` (`0x34`) | `gateway_lb_vip_set_backends` | ✅ |

The REST routes are registered by `GatewayHandlers.registerLBRoutes`
(`pkg/api/rest/gateway_lb_handlers.go`); QUIC sub-opcodes are in
`pkg/api/quic/gateway_lb_handlers.go`. A VIP is keyed by protocol, address
and port on every transport. The add body is
`{address, port, protocol, algorithm?, backends: [{address, port, weight?}]}`;
set-backends takes `{backends: [...]}` and replaces the whole set. A VIP read
returns its `ct_zone`, `group_id` and per-backend `healthy` flag.

A production `platformd` does not wire the load balancer backend yet (see
§5a), so these verbs answer "not configured" on a live platform.

---

## 5a. NAT64 translator

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| NAT64 status | `GET /api/v1/sdn/gateway/nat64/status` | `GetNAT64Status` | `0x39` (`sdk/go/wire/quicwire/gateway_nat64.go`) | `gateway_nat64_status` | ✅ |

> **Production status: routed, not yet backed.** The translator runs in
> `gatewayd`. Today `platformd` does not reach it: it builds the gateway
> service with no NAT64 backend on any transport. On a live platform every
> transport answers "not configured": `Unavailable` on gRPC and Unix, 503 on
> REST, `StatusUnavailable` on QUIC, and "service not available" from MCP.
> That holds even while the `nat64:` section is running and healthy.
>
> Connecting the control plane to gatewayd-resident services is planned and
> awaits a design decision: live IPC over the supervisor seam, or the
> telemetry snapshot. The load balancer (§5) and perf (§6) verbs share the
> same gap. Until it lands, read translator health from `gatewayd` itself
> or from the telemetry snapshot's `nat64` section.
>
> What is proven today:
> - The verb is routed on every transport (`TestNAT64StatusMultiProtocol`).
> - The translator itself works end to end (`make integration-test-nat64`).

Read-only by design: the translator has no runtime verbs. Its `pool6`,
`pool4` and session lifetimes are declarative — they come from the `nat64:`
section and are reconciled, so there is nothing an operator would set over
an API that the desired configuration would not immediately undo. The
session table is the kernel's and is not the platform's to mutate.

What comes back is what the kernel reported, not what the configuration
asked for. `instance_present` false on an `active` service means the
translator's instance disappeared underneath a started section, which is
the failure this surface exists to make visible.

Every transport carries the same nine fields, converted through one shared
function per transport family so the transports cannot drift:

| Field | Meaning |
|---|---|
| `active` | The service is started |
| `instance_present` | The kernel held the instance at the last check |
| `prefix` | The RFC 6052 translation prefix in use |
| `instance` | The kernel instance name |
| `sessions` | Live translation sessions |
| `pool4_used` | Allocated address:port pairs |
| `module_version` | The translator's reported version |
| `flow_count` | Pipeline flows the service holds |
| `last_error` | The last reconcile failure, absent when the last succeeded |

On the wire, REST and MCP carry the bare status object above. QUIC carries
it under `status`, with `last_reconcile` in Unix seconds. gRPC wraps it in
`GetNAT64StatusResponse.status`. The Go SDK's REST, MCP and QUIC adapters
each decode their transport's shape into that reply: REST and MCP through
`sdk/go/services/gateway.DecodeNAT64StatusJSON`, QUIC through its own
category decoder. A missing decoder does not fail loudly. It returns an
empty status, or for QUIC an Internal error once the translator has
reconciled. `TestNAT64StatusResponse_DecodesThroughTheSDK` in
`pkg/api/rest` pins the served JSON to the decoder.

Error mapping, the same on every transport:

| Cause | gRPC / Unix | REST | QUIC | MCP |
|---|---|---|---|---|
| Section not running (may be starting, or refused and fixable in configuration) | `Unavailable` | 503 | `StatusUnavailable` | "service not available" |
| Kernel cannot carry the translator (no retry helps until someone loads the module) | `FailedPrecondition` | 412 | `StatusInvalidRequest` | the error, with the kernel's reason |
| Anything else | `Internal` | 500 | `StatusInternalError` | the error |

QUIC has no failed-precondition byte. It carries this case as
`StatusInvalidRequest`, which is how every QUIC delegate bridges
`FailedPrecondition`. The Go SDK reads that byte as `InvalidArgument`. The
kernel's reason is in the message on every transport.

---

## 6. Performance and datapath statistics

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`) | MCP | Embedded |
|---|---|---|---|---|---|
| Flow-programming measurement | `POST /api/v1/sdn/gateway/perf/flows` | `GetPerfFlows` | `OpGatewayPerfFlows` (`0x36`) | `gateway_perf_flows` | ✅ |
| Datapath statistics | `GET /api/v1/sdn/gateway/perf/datapath` | `GetPerfDatapath` | `OpGatewayPerfDatapath` (`0x37`) | `gateway_perf_datapath` | ✅ |
| Conntrack statistics | `GET /api/v1/sdn/gateway/perf/conntrack` | `GetPerfConntrack` | `OpGatewayPerfConntrack` (`0x38`) | `gateway_perf_conntrack` | ✅ |

**Flow measurement mutates the bridge.** It installs ephemeral flows into the
dedicated perf table 250 under cookie `0xF1BE00FF00000000`, times the install,
and removes them with one cookie-scoped delete
(`pkg/sdn/gateway/services/perf/service.go`). That is why it is a REST `POST`
and why its MCP tool needs `sdn:write` while the two read verbs need
`sdn:read` (`pkg/api/mcp/authz.go`).

The perf sub-opcodes are served by the same shared perf service as the other
transports; when the perf backend is not wired, they return
`StatusUnavailable` rather than failing as unknown opcodes. A production
`platformd` does not wire the perf backend yet (see §5a), so on a live
platform that is what every transport answers.

---

## 7. Network zones at the gateway

Zone CRUD is `SDNService`'s (`CreateNetworkZone` and friends —
[`docs/sdn/api.md`](../sdn/api.md) §5), but the **QUIC** path and the **MCP**
tools are gateway-scoped:

| Capability | REST | gRPC / Unix | QUIC (under `0x2F`, `0x10`–`0x13`) | MCP | Embedded |
|---|---|---|---|---|---|
| List zones | `GET /api/v1/sdn/zones` | `SDNService.ListNetworkZones` | `OpGatewayListNetworkZones` (`0x10`) | `gateway_zone_list` | ✅ |
| Create zone | `POST /api/v1/sdn/zones` | `SDNService.CreateNetworkZone` | `OpGatewayCreateNetworkZone` (`0x11`) | `gateway_zone_create` | ✅ |
| Update zone | `PUT /api/v1/sdn/zones/{name}` | `SDNService.UpdateNetworkZone` | `OpGatewayUpdateNetworkZone` (`0x12`) | `gateway_zone_update` | ✅ |
| Delete zone | `DELETE /api/v1/sdn/zones/{name}` | `SDNService.DeleteNetworkZone` | `OpGatewayDeleteNetworkZone` (`0x13`) | `gateway_zone_delete` | ✅ |

There is no assign-network-to-zone operation (networks are zones since
#708); `0x14` is retired. The zone object and its rules are in
[SDN api.md](../sdn/api.md) §5.

Zones are split across two gRPC services and two MCP prefixes. That is worth
knowing before searching for `sdn_zone_*` tools, which do not exist.

---

## 8. Control-plane liaison

A second REST router under the same `/api/v1/gateway` prefix
(`pkg/webservice/v1/rest/gateway/control_plane.go`) carries the gateway ⇄
control-plane conversation. These routes are served by the **control plane**,
consumed by gateways:

| Method | Path | Purpose | Authorization |
|---|---|---|---|
| GET | `/api/v1/gateway/state` | List reported gateway state | operator surface (see below) |
| GET | `/api/v1/gateway/state/{id}` | One gateway's state | operator surface (see below) |
| DELETE | `/api/v1/gateway/state/{id}` | Forget a gateway's state | operator surface (see below) |
| POST | `/api/v1/gateway/telemetry` | Gateway pushes telemetry | body `gateway_id` **must equal** the client certificate CN |
| GET | `/api/v1/gateway/desired-config/{id}` | Gateway fetches its desired configuration | `{id}` **must equal** the client certificate CN |

`desired-config` is the direction of authority made explicit: the control plane
decides, the gateway fetches. A gateway does not author its own configuration.

The response payload is `{"gateway_id": …, "config": <DesiredConfig>}`, where
`config` is the typed wire contract `gwstate.DesiredConfig`
(`pkg/sdn/gateway/state/desired.go`, #555):

```json
{
  "gateway_id": "gw-01-gateway",
  "version": "rev-4",
  "load_balancer": {"vips": [{"address": "10.0.200.10", "port": 443, "protocol": "tcp",
                             "backends": [{"address": "10.0.100.11", "port": 8443, "weight": 2}]}]},
  "nat": {"snat_internal_cidr": "10.0.100.0/24",
          "dnat": [{"protocol": "tcp", "external": "203.0.113.10:2222", "internal": "10.0.100.5:22"}]}
}
```

Every section is the *complete* desired state of that service, and only
sections a gateway can apply through a live service exist; an unknown key is
refused by the gateway rather than ignored. `version` is optional — a gateway
derives a content revision when it is absent. The gateway's telemetry
`Snapshot.desired_config` (`version`, `applied_at`, `attempted_at`,
`last_error`) reports what happened to the last document. See
[`engineering.md`](engineering.md) §5.

**A gateway reaches only its own record.** On the two gatewayd-facing routes the
control plane derives the caller's identity from the Subject Common Name of the
verified mTLS client certificate and compares it to the `gateway_id` the request
names — exactly, case-sensitively, verbatim (a CN with leading or
trailing whitespace is refused, never trimmed), with no alias or
override mechanism. A
request carrying no verified client certificate is refused **401**
(`ErrGatewayIdentityRequired`); a verified certificate naming another gateway is
refused **403** (`ErrGatewayIdentityMismatch`), and nothing is written or read.
Identity comes from the connection's `VerifiedChains`, so the listener requests
the certificate optionally (`tls.VerifyClientCertIfGiven`) and the TLS stack
verifies it against the configured `ClientCAs` before any handler runs — clients
that present no certificate, such as the WebUI, are unaffected on the shared
listener. Rationale and the field choice:
[`docs/gateway/engineering.md`](engineering.md) §5.

The three `state` routes are the WebUI's fleet-wide read and admin surface, so
they are not bound to a gateway certificate; choosing the operator authorization
they carry is tracked separately.

---

## 9. Trusted reverse proxy

REST is served through `pkg/api/daemon/proxy_rest.go`; QUIC through sub-opcodes
`0x20`–`0x2D` **multiplexed under the gateway category `0x2F`**.

| Capability | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|
| Create route | `CreateRoute` | ✅ | `proxy_route_create` | ✅ |
| Get route | `GetRoute` | ✅ | `proxy_route_get` | ✅ |
| Update route | `UpdateRoute` | ✅ | `proxy_route_update` | ✅ |
| Delete route | `DeleteRoute` | ✅ | `proxy_route_delete` | ✅ |
| List routes | `ListRoutes` | ✅ | `proxy_route_list` | ✅ |
| Create pool | `CreatePool` | ✅ | `proxy_pool_create` | ✅ |
| Get pool | `GetPool` | ✅ | `proxy_pool_get` | ✅ |
| Update pool | `UpdatePool` | ✅ | `proxy_pool_update` | ✅ |
| Delete pool | `DeletePool` | ✅ | `proxy_pool_delete` | ✅ |
| List pools | `ListPools` | ✅ | `proxy_pool_list` | ✅ |
| Get proxy config | `GetProxyConfig` | ✅ | `proxy_config` | ✅ |
| Get proxy status | `GetProxyStatus` | ✅ | `proxy_status` | ✅ |
| Reload proxy config | `ReloadProxyConfig` | ✅ | `proxy_config_reload` | ✅ |
| Get zone matrix | `GetZoneMatrix` | ✅ | `proxy_zone_matrix` | ✅ |

`GetZoneMatrix` is the join between proxy routing and SDN zoning: it reports
which zones may reach which, so a route's reachability is derived rather than
configured twice.

---

## 10. Authorization

Platform tokens carry an `scp` claim as `"<resource>:<action>"`.
The gRPC scope catalog (`pkg/api/grpc/method_permissions.go`) is
**default-deny**: a method absent from it is refused with `PermissionDenied`.

**`GatewayService` is fully scoped** under resource `sdn`: the VIP, snapshot,
perf, IPAM, BGP, status and mode RPCs all carry `sdn:read`, `sdn:write` or
`sdn:delete`. `GetPerfFlows` needs `sdn:write` because it installs and removes
ephemeral flows. **`ProxyService` is fully scoped** under `proxy`
([`docs/proxy/api.md`](../proxy/api.md) §7).

On MCP, the `gateway_ipam_*`, `gateway_lb_*`, `gateway_nat64_status`,
`gateway_zone_*`, `gateway_snapshot*`, `gateway_perf_*`, `gateway_status` and
`gateway_mode_set` tools carry the same `sdn:*` permissions as their gRPC twins:
`gateway_status` needs `sdn:read` like `GetGatewayStatus`, and
`gateway_mode_set` needs `sdn:write` like `SetGatewayMode` (#65). The
`gateway_bgp_*` tools are not classified, so `AuthorizeTool` refuses them for
every caller.

`TestGRPCMethodCatalog_CoversEveryRegisteredMethod` enumerates `GatewayService`
from its registered descriptor, so an RPC added to `gateway.proto` without a
catalog entry fails `make test`.

The admitted-VTEP reads (`GetGatewayAdmittedVTEP`, `ListGatewayAdmittedVTEPs`
and the `gateway_admitted_vtep(s)` MCP tools) require `sdn:read`, the same
scope as the snapshot they are read from. Each entry names the admitted
device's ID, serial and hostname. `sdn:read` is a role permission that a tenant
role can carry, and no transport except REST can yet require a system-tenant
caller (#299), so a tenant granted `sdn:read` sees the fabric's device
identities.

### REST is split by principal, and only the operator half is role-gated (#165)

**Operator half — requires an authenticated `admin`:** the `GatewayService`
surface (`/gateway/status`, `/gateway/mode`, `/gateway/bgp/**`,
`/gateway/ipam/**`) and the fleet-wide control-plane state surface
(`GET /gateway/state`, `GET|DELETE /gateway/state/{id}`). An anonymous BGP
announce is a route hijack; an anonymous IPAM allocation is address exhaustion.

**gatewayd-facing half — NOT role-gated, because it is already
authenticated:** `POST /gateway/telemetry` and `GET
/gateway/desired-config/{id}` require a **verified mTLS client certificate**
and bind the request's `gateway_id` to that certificate's Common Name — 401
without a certificate, 403 when the id names another gateway
(`ControlPlane.authenticatedGateway`). Their caller is gatewayd, whose
credential is a certificate rather than a bearer token, so a role guard in
front of them would break every gateway in the fleet.

The correct reading of that half is **not** "unauthenticated" but
"authenticates differently" — exactly the determination #165 scope item 2 asks
for on each machine-facing surface. The division is by principal, not by verb,
and it is enforced by `ControlPlane.RegisterRoutes` versus
`ControlPlane.RegisterGatewayFacingRoutes`, asserted exactly and for
disjointness in that package's tests.

Which operator authorization the `/gateway/state` routes should carry was
previously left open in the code as an owner decision. #165 answers it with the
same RBAC role guard #159 established for the rest of the API.

This changes the REST position only. The gRPC, Unix, MCP and embedded
positions described above are unchanged. See
[`docs/auth/architecture.md`](../auth/architecture.md) §6c.

---

## 11. Status and error mapping

| QUIC byte | Name | REST | Gateway cause |
|---|---|---|---|
| `0x00` | `StatusOK` | 200 | — |
| `0x01` | `StatusInvalidRequest` | 400 | Malformed prefix, pool, VIP or route; on REST a host precondition is 412 instead (the NAT64 module, §5a) |
| `0x02` | `StatusNotFound` | 404 | Unknown pool, VIP, route or gateway ID |
| `0x03` | `StatusUnauthorized` | 401 | Proxy auth chain rejected the request |
| `0x04` | `StatusInternalError` | 500 | BGP speaker or datapath failure |
| `0x06` | `StatusAlreadyExists` | 409 | Duplicate pool, VIP or route |
| `0x07` | `StatusPermissionDenied` | 403 | Missing scope; proxy policy denied |
| `0x08` | `StatusResourceExhausted` | 429 | IPAM pool exhausted |
| `0x0A` | `StatusUnavailable` | 503 | A service section not enabled or its backend not wired |

**`StatusUnavailable` is the normal answer for a disabled service section.** A
gateway with `bgp` off answers BGP calls with 503, not 404 — the capability
exists and is switched off, which is a different thing from not existing.

Two conditions share that 503, and they are told apart by a
`google.rpc.ErrorInfo` detail on the status, not by the message text:

| Condition | Detail | Client reads it as |
|---|---|---|
| No gateway service on this node (a control plane) | `ErrorInfo{reason: SERVICE_NOT_CONFIGURED, domain: go-trusted-platform, metadata.service: gateway}` | topology — render the role state |
| Configured but stopped, or a transient backend failure | none | an error to surface |

REST lifts the detail into the error body's `reason`/`service` fields, so the
same rule holds on every transport. The `error` prose is operator-facing and is
explicitly **not** a contract. See [`docs/web/api.md`](../web/api.md) §4 for the
platform-wide picture.

---

## 12. Versioning

REST under `/api/v1`; gRPC package `platform.v1`. The one deprecated element is
`GatewayMode` and its `SetGatewayMode` RPC / `gateway_mode_set` tool /
`POST /api/v1/gateway/mode` route — retained for compatibility during the
migration to config-driven service sections.
