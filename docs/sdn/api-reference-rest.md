# SDN REST API Reference

Base URL: `https://localhost:8443/api/v1/sdn`

All endpoints require mTLS / platform JWT authentication. Handlers:
`pkg/api/rest/sdn_handlers.go`.

## Bridge Endpoints

```http
POST   /api/v1/sdn/bridges          # Create bridge
GET    /api/v1/sdn/bridges          # List bridges
GET    /api/v1/sdn/bridges/{id}     # Get bridge
DELETE /api/v1/sdn/bridges/{id}     # Delete bridge
```

Create request body carries the bridge config (`id`, `name`, `type`
[`ovs`|`linux`|`vxlan`], optional `datapath_id`, `fail_mode`, `stp`,
`rstp`, `mtu`). List supports `type`, `status`, `limit`, and `cursor`
query parameters.

## Port Endpoints

```http
POST   /api/v1/sdn/bridges/{id}/ports                 # Add port
GET    /api/v1/sdn/bridges/{id}/ports                 # List ports
DELETE /api/v1/sdn/bridges/{id}/ports/{port}          # Remove port
GET    /api/v1/sdn/bridges/{id}/ports/{port}/state    # Get port state
PUT    /api/v1/sdn/bridges/{id}/ports/{port}/state    # Set port state
GET    /api/v1/sdn/bridges/{id}/ports/{port}/stats    # Port statistics
```

The state and stats routes read the port's Open vSwitch interface row. State
answers `port_number` (ofport), `admin_state`, `oper_state` (the link state),
`link_state`, `speed` and `duplex`. Stats answers the interface counters:
`rx_`/`tx_` `packets`, `bytes`, `dropped` and `errors`, plus `rx_frame_err`,
`rx_over_err`, `rx_crc_err` and `collisions`.

Set-state takes `{"admin_state": "up"|"down"}` (case-insensitive; anything else
is `400`), sets it in Open vSwitch, and answers the state read back. An
unknown port is `404`.

The webservice router (`pkg/webservice/v1/rest/sdn/`) serves the same two state
routes through the gRPC `SDNService`. It takes the same set-state body and
answers `bridge_id`, `port_id` and `admin_state`; it has no interface row, so
the link fields are absent. The Go SDK's REST `SetPortState` uses this route on
either server and reads those three fields.

The body may also carry `ingress_rate` (bps) and `ingress_burst` (bits). A
non-zero `ingress_rate` sets the interface's Open vSwitch ingress policing
(`ingress_policing_rate`/`ingress_policing_burst`, stored in kbps and kb); `0`
or absent leaves the current policing as it is. Each value must be `0` or a
whole multiple of 1000, and a burst needs a rate; anything else is `400`
before any state changes. An interface that disappears before policing is
applied is `404`.

`egress_rate` (bps) and `egress_burst` (bits) shape what the port transmits.
A non-zero `egress_rate` gives the port a `linux-htb` Open vSwitch QoS whose
queue 0 carries the rate and burst, stored as given in bps and bits; `0` or
absent leaves the current shaping as it is, and `egress_burst` `0` lets Open
vSwitch pick the burst. Any rate is accepted, but a burst needs a rate; a burst
without one is `400` before any state changes. Shaping set by an earlier
request is replaced and its rows deleted; a QoS something else attached is
detached and left in the database. A port that disappears before shaping is
applied is `404`.

## Flow Endpoints

```http
POST   /api/v1/sdn/flows                              # Add flow
GET    /api/v1/sdn/flows                              # List flows
DELETE /api/v1/sdn/flows/{id}                         # Delete flow

# Bridge-scoped aliases
POST   /api/v1/sdn/bridges/{id}/flows                 # Add flow to bridge
GET    /api/v1/sdn/bridges/{id}/flows                 # List bridge flows
DELETE /api/v1/sdn/bridges/{id}/flows/{flow_id}       # Delete bridge flow
```

Flow bodies carry `id`, `table`, `priority`, match fields (`in_port`,
`dl_src`, `dl_dst`, `dl_type`, `nw_src`, `nw_dst`), and `actions`.

## VLAN Endpoints

```http
POST   /api/v1/sdn/vlans                              # Create VLAN
GET    /api/v1/sdn/vlans?bridge_id={bridge}           # List a bridge's VLANs
DELETE /api/v1/sdn/vlans/{vlan_id}?bridge_id={bridge} # Delete VLAN
```

These routes call the daemon's `SDNService` — the same operations and state
as gRPC `CreateVLAN`, `ListVLANs` and `DeleteVLAN`.

Create body: `vlan_id` (1–4095), `bridge_id` (bridge name or ID), optional
`name`, `ports` (tagged with the VLAN) and `labels`. Create answers `201`
with the VLAN object; list answers `200` with `{vlans, count, timestamp}`:

```json
{
  "id": "vlan-br0-100",
  "vlan_id": 100,
  "name": "tenant-a",
  "bridge_id": "br0",
  "ports": ["p1"],
  "port_count": 1,
  "created_at": "2026-10-13T12:00:00Z"
}
```

Delete answers `200` with
`{"resource_id": "100", "resource_type": "vlan", "action": "deleted", "success": true, "message": "VLAN deleted successfully"}`.

Errors: `400` for a malformed body, a non-numeric or out-of-range
`vlan_id`, or a missing `bridge_id`; `404` for an unknown bridge or VLAN;
`409` when the bridge already carries the VLAN ID; `503` when the daemon
runs without an SDN service.

## Policy Endpoints

```http
POST   /api/v1/sdn/policies         # Apply policy
GET    /api/v1/sdn/policies         # List policies
GET    /api/v1/sdn/policies/{id}    # Get policy
DELETE /api/v1/sdn/policies/{id}    # Delete policy
```

These routes call the daemon's `SDNService` — the same operations and state
as gRPC `ApplyPolicy`, `ListPolicies`, `GetPolicy` and `DeletePolicy`. The
webservice serves apply with the same body and answer (a duplicate name is
`400` there), and the SDK's REST client sends `ApplyPolicy` to it in this form.

Apply body: `name` (required), optional `id`, `description`, `type`
(`acl`, `qos`, `nat`, `firewall`, `routing`), `priority`, `enabled`,
`rules`, `targets` and `schedule`:

```json
{
  "name": "web",
  "type": "acl",
  "priority": 10,
  "enabled": true,
  "rules": [
    {"rule_id": "r1", "priority": 1, "source_ip": "10.0.0.0/24",
     "destination_port": 22, "protocol": "tcp", "action": "deny", "log": true}
  ],
  "targets": [{"type": "bridge", "id": "br0", "direction": "ingress"}],
  "schedule": {"start_time": "08:00", "end_time": "18:00",
               "days": ["mon", "tue"], "timezone": "UTC", "enabled": true}
}
```

A rule matches on `source_ip`, `destination_ip`, `source_port`,
`destination_port`, `protocol`, `direction`, `interface`, `vlan_id`, `dscp`
and `application`, and carries `action` (`allow`, `deny`, `rate-limit`,
`redirect`, `mirror`, `log`), `action_value`, `log` and `counter`. A target
`type` is `bridge`, `port`, `vlan` or `interface`. An empty enum is left
unspecified. The policy object has no `labels`.

Apply answers `201` with the policy object: the body's fields plus `status`,
`hit_count`, `byte_count`, `created_at` and `updated_at`. List takes optional
`type` and `target_id` filters and answers `200` with
`{policies, count, timestamp}`. Get and delete take the policy ID or name;
delete answers `200` with
`{"resource_id": "web", "resource_type": "policy", "action": "delete", "success": true, "message": "policy deleted successfully"}`.

Errors: `400` for a malformed body, a missing `name`, or an unknown `type`,
rule `action` or target `type`; `404` for an unknown policy; `409` when a
policy with the same name exists; `503` when the daemon runs without an SDN
service.

## Topology

```http
GET /api/v1/sdn/topology            # Bridges, ports, and flows summary
```

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
