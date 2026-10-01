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

Set-state request body accepts `admin_state` (`up`|`down`) and optional
`ingress_rate` / `egress_rate` limits (bps).

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
POST   /api/v1/sdn/vlans            # Create VLAN
GET    /api/v1/sdn/vlans            # List VLANs
DELETE /api/v1/sdn/vlans/{id}       # Delete VLAN
```

## Policy Endpoints

```http
POST   /api/v1/sdn/policies         # Apply policy
GET    /api/v1/sdn/policies         # List policies
GET    /api/v1/sdn/policies/{id}    # Get policy
DELETE /api/v1/sdn/policies/{id}    # Delete policy
```

Policy bodies carry `id`, `name`, `type` (`acl`, `qos`, `nat`,
`firewall`, `routing`), `priority`, `bridge_id`, and `enabled`.

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
