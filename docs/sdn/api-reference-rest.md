# SDN REST API Reference

> **Status: REFERENCE** · Last verified: 2026-10-30
> The `/api/v1/sdn` routes of platformd's two REST stacks.

Base URL: `https://localhost:8443/api/v1/sdn`

Two REST stacks serve `/api/v1/sdn`, and which one runs depends on how
platformd starts (the overlay has the same split, see
[overlay/api-reference-rest.md](overlay/api-reference-rest.md)):

| Property | Webservice | Daemon-only REST (`serve --enable-rest`) |
|----------|------------|------------------------------------------|
| Handlers | `pkg/webservice/v1/rest/sdn/` | `pkg/api/rest/sdn_handlers.go` |
| Authentication | platform session, `admin` role on every route (`pkg/webservice/v1/router.go`) | mTLS, then the REST scope guard: a `Bearer` platform token or the operator certificate, holding the route's `sdn` scope (see Scopes) |
| Response body | the platform envelope (`{code, error, success, payload}`) with the response message as `payload` | the response message itself |
| Unknown body fields, query parameters | ignored | `400` |

## Wire Shape (#445)

Both stacks call the daemon's gRPC `SDNService` and speak its `platform.v1`
messages. Every bridge, port, flow, VLAN and policy route reads the request
message of its method as its body and answers that method's response
message, both in the proto JSON mapping (protojson): fields are
lowerCamelCase (`bridgeId`, `adminState`), enums are their names
(`BRIDGE_TYPE_OVS`, `POLICY_TYPE_QOS`), 64-bit integers are strings and bytes
are base64. snake_case field names are read too. A body that is not JSON or
carries a wrong type is `400` and the service is not called. Path and query
values fill the request fields of the same name (`bridge_id`, `port_id`,
`vlan_id`, `policy_id`) and override the body's. On the daemon a dotted query
name reaches into a message field and a label key follows the map name, so a
list request pages and selects with `pagination.page`, `pagination.pageSize`
and `selector.matchLabels.<key>`; the JavaScript SDK sends exactly these, and
the old `page`, `limit` and `label_<key>` names are `400`. Every route answers `200`,
creates included. The zone routes keep the REST zone document (see Network
Zone API). The Go SDK's REST transport uses this table against either stack.

A service error maps to its HTTP status: `InvalidArgument` is `400` (the
webservice also maps `OutOfRange` to `400`), `NotFound` `404`,
`AlreadyExists` and `FailedPrecondition` `409` (#665), `Unavailable` (or no SDN
service) `503`, and anything else `500`. The daemon's error body is
`{error, code, timestamp}`.

| Route | Body | Response | Stack |
|-------|------|----------|-------|
| `POST /bridges` | `CreateBridgeRequest` | `CreateBridgeResponse` | both |
| `GET /bridges` | `ListBridgesRequest` (optional) | `ListBridgesResponse` | both |
| `GET /bridges/{id}` | — | `GetBridgeResponse` | both |
| `DELETE /bridges/{id}` | — | `DeleteBridgeResponse` | both |
| `POST /bridges/{bridge_id}/ports` | `AddPortRequest` | `AddPortResponse` | both |
| `GET /bridges/{bridge_id}/ports` | `ListPortsRequest` (optional) | `ListPortsResponse` | both |
| `DELETE /bridges/{bridge_id}/ports/{port_id}` | — | `DeletePortResponse` | both |
| `GET /bridges/{bridge_id}/ports/{port_id}/state` | — | `GetPortResponse` | both |
| `PUT /bridges/{bridge_id}/ports/{port_id}/state` | `SetPortStateRequest` | `SetPortStateResponse` | both |
| `GET /bridges/{bridge_id}/ports/{port_id}/stats` | — | `GetPortStatsResponse` | both |
| `POST /bridges/{bridge_id}/ports/{port_id}/auth` | `AuthenticatePortRequest` | `AuthenticatePortResponse` | both |
| `DELETE /bridges/{bridge_id}/ports/{port_id}/auth` | — | `RevokePortAuthResponse` | both |
| `POST /flows` | `AddFlowRequest` | `AddFlowResponse` | both |
| `POST /bridges/{name}/flows` | `AddFlowRequest` | `AddFlowResponse` | webservice |
| `GET /flows?bridge_id=`, `GET /bridges/{bridge_id}/flows` | `ListFlowsRequest` (optional) | `ListFlowsResponse` | both |
| `DELETE /flows` | `DeleteFlowRequest` | `DeleteFlowResponse` | both |
| `POST /vlans` | `CreateVLANRequest` | `CreateVLANResponse` | both |
| `GET /vlans?bridge_id=` | `ListVLANsRequest` (optional) | `ListVLANsResponse` | both |
| `POST`, `GET` `/bridges/{bridge_id}/vlans` | as `/vlans` | as `/vlans` | webservice |
| `DELETE /vlans/{vlan_id}?bridge_id=` | — | `DeleteVLANResponse` | daemon |
| `POST /policies` | `ApplyPolicyRequest` | `ApplyPolicyResponse` | both (webservice answers `201`) |
| `GET /policies` | `ListPoliciesRequest` (optional) | `ListPoliciesResponse` | both |
| `GET /policies/{policy_id}` | — | `GetPolicyResponse` | both |
| `DELETE /policies/{policy_id}` | — | `DeletePolicyResponse` | daemon |

### Scopes (daemon stack, #997)

Every daemon route needs the `sdn` scope the gRPC catalog gives its
`SDNService` rpc: no credential answers `401`, a credential without the scope
`403`.

| Route | Scope |
|-------|-------|
| every `GET` (bridges, ports, port state and stats, flows, VLANs, policies, zones) | `sdn:read` |
| `POST /bridges`, `POST /bridges/{bridge_id}/ports`, `PUT .../ports/{port_id}/state`, `POST .../ports/{port_id}/auth`, `POST /flows`, `POST /vlans`, `POST /policies`, `POST /zones`, `PUT /zones/{name}` | `sdn:write` |
| `DELETE /bridges/{bridge_id}/ports/{port_id}/auth` (`RevokePortAuth`) | `sdn:write` |
| `DELETE /bridges/{id}`, `DELETE .../ports/{port_id}`, `DELETE /flows`, `DELETE /vlans/{vlan_id}`, `DELETE /policies/{policy_id}`, `DELETE /zones/{name}` | `sdn:delete` |

Until #445 both stacks answered flat REST documents (a bridge as `name`,
`type` `"ovs"` and `created_at`; a delete as `{success, message}`; the port
state as `bridge_id`, `port_id` and `admin_state`), read flat REST bodies
(the daemon refused the SDK's `adminState`), answered creates with `201`, and
the daemon served `GET /topology`, `DELETE /flows/{id}` and the bridge-scoped
flow routes, which no client called. Those routes are gone.

A flow or VLAN created through `/bridges/{name}/flows` or
`/bridges/{bridge_id}/vlans` must still carry its `config`; the path fills in
the config's bridge, never the rest of the request.

## Bridges

`CreateBridgeRequest.config` carries the bridge `name` (required), `type`,
`stpEnabled`, `mtu`, `controllers`, `options` and `labels`. The option
`fail_mode` is written in the same Open vSwitch transaction that creates the
bridge, so a `secure` bridge never runs as a standalone learning switch; an
invalid `fail_mode` is `400` and creates nothing. A bridge is addressed by
name or UUID.

## Ports

`AddPortRequest.config` carries the port `name` (required) and an optional
`type`, the Open vSwitch interface type written in the same transaction that
creates the port. `PORT_TYPE_UNSPECIFIED` attaches the existing kernel device
of the port's name; a type Open vSwitch does not implement adds nothing.

The state and stats routes read the port's Open vSwitch interface row: get
answers the `Port` with its admin and link state; stats answers the interface
counters.

`SetPortStateRequest` carries `adminState` (`up` or `down`), `ingressRate`
and `ingressBurst`, `egressRate` and `egressBurst`. An unknown port is `404`;
it is checked before the admin state. A non-zero `ingressRate` (bps) sets the
interface's Open vSwitch ingress policing (`ingress_policing_rate`/
`ingress_policing_burst`, stored in kbps and kb); `0` leaves the current
policing as it is. Each value must be `0` or a whole multiple of 1000, and a
burst needs a rate; anything else is `400` before any state changes.

A non-zero `egressRate` (bps) gives the port a `linux-htb` Open vSwitch QoS
whose queue 0 carries the rate and `egressBurst` (bits); `0` leaves the
current shaping as it is, and a burst `0` lets Open vSwitch pick it. A burst
without a rate is `400` before any state changes. Shaping set by an earlier
request is replaced and its rows deleted; a QoS something else attached is
detached and left in the database. A port that disappears before policing
or shaping is applied is `404`.

## Port Authentication

The `/auth` routes take an `AuthenticatePortRequest` (`certificate` base64,
`format`); the path names the bridge and port. Every request is refused with
`409` and the message `sdn/policy: <operation> is refused: port
authentication is not enforced on the switch` (`policy.ErrPortAuthNotEnforced`,
`FailedPrecondition`): nothing enforces port authentication on the switch, so
nothing is recorded. The Go SDK's REST transport reads that `409` as
`AlreadyExists` on the `POST` and as `FailedPrecondition` on the `DELETE`, and
keeps the message. [api.md](api.md) §4 names what is
missing. Until #304 these routes answered `200` for any certificate inside
its validity window, and the webservice answered `500` for a
`FailedPrecondition`; until #445 the daemon did not serve them.

## Flows

`AddFlowRequest.config` carries the `bridgeId`, `table`, `priority`, `match`
and `actions`. A flow's ID is its cookie, so `DELETE /flows` with
`{"bridgeId": ..., "flowId": ...}` removes exactly that flow; an ID that names
no flow is `400`.

The service writes every `match` field and action into the Open vSwitch flow
(`pkg/api/daemon/sdn_flow_codec.go`). IP matches add the `dl_type` their
address family needs, and a TCP or UDP port implies its `ipProto`. The actions
are `OUTPUT` (no port means `NORMAL`), `DROP`, `SET_VLAN`, `STRIP_VLAN`,
`SET_FIELD`, `GOTO_TABLE` (to a later table only) and `CONTROLLER`. A flow
that OVS cannot install exactly is `400` and nothing is installed. Examples are
`metadata`, a value out of range, TCP and UDP ports together, and an
unspecified action. A listed flow carries its table, priority, match, actions,
timeouts and packet, byte and duration counters. A match term with no proto
field is returned in `match.metadata`.

## VLANs

`CreateVLANRequest.config` carries `vlanId` (1–4095), `bridgeId` (bridge name
or ID), optional `name`, `ports` (tagged with the VLAN) and `labels`. The
daemon deletes with `DELETE /vlans/{vlan_id}?bridge_id=`. Errors: `400` for a
malformed body, an out-of-range or non-numeric `vlan_id`, or a missing
bridge; `404` for an unknown bridge or VLAN; `409` when the bridge already
carries the VLAN ID.

## Policies

`ApplyPolicyRequest` carries an optional `policyId` and the `config`
(`PolicyConfig`): `name` (required), `description`, `type`
(`POLICY_TYPE_ACL`, `POLICY_TYPE_QOS`, ...), `priority`, `enabled`, `rules`,
`targets` and `schedule`:

```json
{
  "config": {
    "name": "web",
    "type": "POLICY_TYPE_ACL",
    "priority": 10,
    "enabled": true,
    "rules": [
      {"ruleId": "r1", "priority": 1,
       "match": {"sourceIp": "10.0.0.0/24", "destinationPort": 22, "protocol": "tcp"},
       "action": "POLICY_RULE_ACTION_DENY", "log": true}
    ],
    "targets": [{"type": "POLICY_TARGET_TYPE_BRIDGE", "id": "br0", "direction": "ingress"}]
  }
}
```

List takes the optional `type` (`acl`, `qos`, ...) and `target_id` query
parameters. Get and delete take the policy ID or name. Errors: `400` for a
missing `name`; `404` for an unknown policy; `409` when a policy with the
same name exists.

## Error Codes

HTTP status codes:

- 400: Bad Request (invalid parameters)
- 401: Unauthorized
- 404: Not Found
- 409: Conflict (e.g., bridge exists)
- 500: Internal Server Error
- 503: Service Unavailable (the backing service is not wired)

## Network Zone API

Base path: `/api/v1/sdn/zones`

Two stacks serve these paths with the same object shapes: the webservice
(`pkg/webservice/v1/rest/sdn/zones.go`, always mounted when the SDN
service exists — the surface the WebUI uses) wraps each response in the
standard platform envelope (`{code, error, success, payload}`); the
daemon's standalone REST server (`pkg/api/rest/sdn_handlers.go`, only
when `EnableREST` is set) returns the body bare.

On the webservice these routes are admin-gated — a zone defines what may
reach what, so every endpoint below requires an authenticated caller
holding `admin` and answers 401 or 403 otherwise.

The zone object (`pkg/sdn/gateway.ZoneSpec` in requests,
`pkg/sdn/gateway.ZoneView` in responses):

| Field | Type | Notes |
|---|---|---|
| `name` | string | Lowercase DNS label; not `platform`, `tenant`, `public` or `trusted` |
| `offset` | integer | 0–8 for the built-ins (fixed); 9–99 for an owner-defined zone |
| `port_classes` | string[] | Fixed for built-ins; owner-defined zones: `gateway` and/or `hypervisor` |
| `internet_ingress` | bool | Accepts inbound internet traffic |
| `isolate_from` | string[] | Zones this zone never sends to |
| `allow_to` | `{zone, services}`[] | Directed paths; empty `services` allows all |
| `services` | string[] | Services permitted inside the zone |
| `isolate` | bool | Deny everything except `allow_to` paths |
| `oob` | bool | Built-in `management` only |
| `lifecycle_role` | string | Built-in `provisioning` and `quarantine` only |
| `privileged_access` | `{reason, approved_by}` | Required for an `allow_to` path into `control-plane` or `management` beyond the reference defaults; audited |
| `numbering` | `{vlan, subnet4, subnet6, gateway}` | Response only; present when the node has an `sdn.environment` |
| `restart_required` | bool | Response only; true after every accepted mutation |
| `created_at`, `updated_at` | RFC 3339 | Response only |

### POST /api/v1/sdn/zones

Create an owner-defined zone.

**Request body:**
```json
{
  "name": "lab",
  "offset": 9,
  "port_classes": ["hypervisor"],
  "isolate": true,
  "allow_to": [{"zone": "control-plane", "services": ["dns"]}],
  "privileged_access": {"reason": "lab resolver", "approved_by": "owner"}
}
```

**Response 201:**
```json
{
  "name": "lab",
  "offset": 9,
  "port_classes": ["hypervisor"],
  "isolate": true,
  "allow_to": [{"zone": "control-plane", "services": ["dns"]}],
  "privileged_access": {"reason": "lab resolver", "approved_by": "owner"},
  "numbering": {"vlan": 409, "subnet4": "10.4.9.0/24", "subnet6": "fd12:3456:789a:409::/64", "gateway": "10.4.9.1"},
  "restart_required": true,
  "created_at": "2026-10-01T00:00:00Z",
  "updated_at": "2026-10-01T00:00:00Z"
}
```

**Errors:** 400 (missing name, malformed body, or the zone or numbering
validation fails — the message names the rule), 409 (the zone exists; the
built-ins always do).

### GET /api/v1/sdn/zones

List the zones in offset order. Optional `lifecycle_role` query parameter
filters results.

**Query parameters:**
- `lifecycle_role` — `provisioning` or `quarantine` (empty returns all)

**Response 200:**
```json
{
  "zones": [
    {
      "name": "provisioning",
      "offset": 5,
      "port_classes": ["gateway", "hypervisor"],
      "isolate": true,
      "lifecycle_role": "provisioning",
      "services": ["dhcp", "tftp", "http", "dns", "acme"],
      "allow_to": [{"zone": "control-plane", "services": ["tftp", "http", "dns", "acme"]}],
      "numbering": {"vlan": 405, "subnet4": "192.0.2.0/24", "gateway": "192.0.2.1"},
      "created_at": "2026-10-01T00:00:00Z",
      "updated_at": "2026-10-01T00:00:00Z"
    }
  ],
  "count": 1,
  "timestamp": "2026-10-01T00:00:00Z"
}
```

### PUT /api/v1/sdn/zones/{name}

Tune a built-in zone's policy or replace an owner-defined zone. The body's
fields replace the zone's policy as a whole; `name` is taken from the path
(on the webservice a mismatched body `name` is refused). A built-in keeps
its offset, port classes, lifecycle role and OOB flag; changing them is a
400.

**Response 200:** the zone object, `restart_required: true`. 404 when the
zone does not exist.

### DELETE /api/v1/sdn/zones/{name}

Delete an owner-defined zone, or omit an optional built-in. `fabric`,
`provisioning`, `quarantine` and `control-plane` cannot be removed (400).

**Response 200:**
```json
{"deleted": true, "restart_required": true}
```

There is no `PUT /api/v1/sdn/networks/{network}/zone`: networks are zones.
