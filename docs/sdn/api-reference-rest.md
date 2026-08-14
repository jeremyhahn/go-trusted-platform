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

### POST /api/v1/sdn/zones

Create a new network trust zone.

**Request body:**
```json
{
  "name": "dmz",
  "internet_ingress": true,
  "isolate": false,
  "isolate_per_tenant": false,
  "oob": false,
  "lifecycle_role": ""
}
```

**Response 201:**
```json
{
  "name": "dmz",
  "internet_ingress": true,
  "restart_required": false,
  "created_at": "2026-06-12T00:00:00Z",
  "updated_at": "2026-06-12T00:00:00Z"
}
```

### GET /api/v1/sdn/zones

List all network trust zones. Optional `lifecycle_role` query parameter filters results.

**Query parameters:**
- `lifecycle_role` — `provisioning` or `quarantine` (empty returns all)

**Response 200:**
```json
{
  "zones": [
    {
      "name": "trusted",
      "isolate": false,
      "created_at": "2026-06-12T00:00:00Z",
      "updated_at": "2026-06-12T00:00:00Z"
    }
  ],
  "count": 1,
  "timestamp": "2026-06-12T00:00:00Z"
}
```

### PUT /api/v1/sdn/zones/{name}

Update policy settings of an existing zone.

**Request body:** same fields as create (except `name`).

**Response 200:** zone object with `restart_required` set when flow matrix
must be rebuilt.

### DELETE /api/v1/sdn/zones/{name}

Delete a zone by name. Fails when the zone is the sole holder of a required
lifecycle role.

**Response 200:**
```json
{"deleted": true, "restart_required": false}
```

### PUT /api/v1/sdn/networks/{network}/zone

Assign a network segment to a trust zone.

**Request body:**
```json
{"zone": "trusted"}
```

**Response 200:**
```json
{"success": true, "restart_required": true}
```
