# Device MCP API Reference

Endpoint: `localhost:9445` (HTTPS) or `stdio`

## Overview

The Device API is exposed via the Model Context Protocol (MCP) for AI/LLM integration. MCP enables LLMs to query device inventory, manage profiles, and perform attestation operations.

## Tools

Device ids are passed as decimal **strings** (`device_id`). Every device result
is the stored device entity as JSON (`id`, `serial`, `model`, `ek_cert`,
`att_pub`, `attest_cert`, `signing_pub`, `hash_algo`, `state`, …), with `id` a
JSON number.

### device_register

Register a new device; the server assigns its id. Each argument is stored under
the device field of the same name, and the result is the created device.

```json
{
  "name": "device_register",
  "inputSchema": {
    "type": "object",
    "properties": {
      "serial": {"type": "string", "description": "Device serial number"},
      "model": {"type": "string", "description": "Device model"},
      "ek_cert": {"type": "string", "description": "PEM TPM endorsement key certificate"},
      "attest_pub": {"type": "string", "description": "Attestation public key"},
      "attest_cert": {"type": "string", "description": "PEM attestation key certificate issued by the platform CA"},
      "signing_pub": {"type": "string", "description": "Signing public key"},
      "hash_algo_id": {"type": "integer", "description": "TPM hash algorithm identifier"}
    },
    "required": ["serial"]
  }
}
```

A missing `serial` is refused; a `hash_algo_id` outside the uint32 range is
refused before it reaches the service.

### device_get

```json
{
  "name": "device_get",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "string", "description": "Device ID"}
    },
    "required": ["device_id"]
  }
}
```

### device_find_by_serial

```json
{
  "name": "device_find_by_serial",
  "inputSchema": {
    "type": "object",
    "properties": {
      "serial": {"type": "string", "description": "Device serial number"}
    },
    "required": ["serial"]
  }
}
```

### device_update

Update a device's `model` or `serial` and return the stored device; omitted
fields are kept. The attestation fields are server-owned and are not changed
by this tool.

```json
{
  "name": "device_update",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "string", "description": "Device ID"},
      "model": {"type": "string", "description": "New device model"},
      "serial": {"type": "string", "description": "New device serial number"}
    },
    "required": ["device_id"]
  }
}
```

### device_delete

```json
{
  "name": "device_delete",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "string", "description": "Device ID"}
    },
    "required": ["device_id"]
  }
}
```

### device_list

```json
{
  "name": "device_list",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_type": {"type": "string", "description": "Filter by device type"},
      "status": {"type": "string", "description": "Filter by status"}
    }
  }
}
```

### device_attest

Verify TPM quote evidence submitted for a device. Permission `device:write`:
a verified quote can seed the profile's PCR baseline and a failed one
quarantines the device ([api.md §7](api.md#7-authorization)).

The tool takes the whole evidence document as one base64 argument, not the
quote fields spread across separate arguments: every transport carries the
same JSON-encoded `DeviceQuoteEvidence`, so the shape cannot fork per
surface.

```json
{
  "name": "device_attest",
  "description": "Verify device attestation evidence",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "string", "description": "Device ID"},
      "evidence": {"type": "string", "description": "Base64-encoded attestation evidence"}
    },
    "required": ["device_id", "evidence"]
  }
}
```

`evidence` decodes to:

```json
{
  "quote": "<base64 marshaled TPMS_ATTEST>",
  "signature": "<base64 AK signature over the quote>",
  "nonce": "<base64 anti-replay nonce embedded in the quote>",
  "pcrs": {"0": "<base64 SHA-256>", "7": "<base64 SHA-256>"}
}
```

The reply is the verdict, not a bare flag: `verified`, `signature_valid`,
`nonce_valid`, `pcrs_valid`, `ak_certificate_verified`,
`attestation_status`, `message`, and the PCR-baseline trio. A quote that
fails verification is a successful call with `verified: false`.

### device_record_attest_cert

Record (or re-record) a device's attestation certificate on its platform
record without re-enrolling the device. Permission `device:write`. The
control plane fails closed — the certificate must parse, chain to the
platform CA, carry `tcg-cap-verifiedTPMRestricted` and certify the device's
enrolled attestation key — and a refusal names every candidate it evaluated.
`clear_on_refusal` (default `false`) clears a stored certificate every
candidate refused instead of returning the refusal, audited as
`device_attest_cert_cleared`.
The result carries the `RecordAttestationCertificateResponse` fields with
proto names (`device_id`, `changed`, `source`, `source_detail`, `reissued`,
`subject`, `certificate_serial`, `not_after`, `attest_cert`, `cleared`,
`refusal`). See
[api.md §4.5](api.md#45-recording-the-attestation-certificate-without-re-enrolling-473).

```json
{
  "name": "device_record_attest_cert",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "string", "description": "Device ID"},
      "reissue": {"type": "boolean", "description": "Ask the platform CA to issue a fresh attestation certificate over the enrolled attestation public key when no stored certificate passes the preflight"},
      "clear_on_refusal": {"type": "boolean", "description": "Clear the stored attestation certificate when every candidate is refused (default false); an audit event records the clear"}
    },
    "required": ["device_id"]
  }
}
```

### device_boot_certificate

A diskless node's proof-of-possession request for its recorded IDevID chain
([api.md §4.6](api.md#46-diskless-boot-delivery-690)). No permission is required:
the service authenticates the request itself. `identity` is the claimed device
identity and `signature` is base64 (the proof over the identity and the
channel nonce). MCP carries no TLS connection, so the nonce is empty and the
service refuses the request with `-32007` (`FailedPrecondition`,
`ErrBootChannelRequired`); the tool exists so every transport enforces the
same check. A `signature` that is not base64 is `-32602`.

```json
{
  "name": "device_boot_certificate",
  "inputSchema": {
    "type": "object",
    "properties": {
      "identity": {"type": "string", "description": "Claimed device identity"},
      "signature": {"type": "string", "description": "Base64 proof-of-possession signature"}
    },
    "required": ["identity", "signature"]
  }
}
```

### device_boot_delivery

A diskless node's attestation evidence in, network profile and CA bundle out
([api.md §4.6](api.md#46-diskless-boot-delivery-690)). No permission is required.
`evidence` is base64. The node's identity is the client certificate of the
connection, which MCP does not have, so the service refuses the request with
`-32007` (`FailedPrecondition`). `evidence` that is not base64 is `-32602`.

```json
{
  "name": "device_boot_delivery",
  "inputSchema": {
    "type": "object",
    "properties": {
      "evidence": {"type": "string", "description": "Base64 attestation evidence"}
    },
    "required": ["evidence"]
  }
}
```

### device_disable / device_enable

The operator's lifecycle transitions. Permission `device:write`.
`device_disable` blocks the device's switch port and records it `suspended`;
`device_enable` re-admits a `suspended` device to the quarantine zone, records
it `quarantined` and requests re-attestation. Both are refused when no SDN
policy engine runs, when the device has no switch port, or when the
transition is not allowed. The result carries the `DeviceLifecycleResponse`
fields (`device_id`, `state`, `previous_state`, `state_reason`,
`reattestation_requested`). See
[api.md §4.7](api.md#47-operator-disable-and-enable-250).

```json
{
  "name": "device_disable",
  "inputSchema": {
    "type": "object",
    "properties": {
      "device_id": {"type": "string", "description": "Device ID"},
      "reason": {"type": "string", "description": "Why the device is disabled (at most 256 bytes; default \"disabled\")"}
    },
    "required": ["device_id"]
  }
}
```

`device_enable` takes only `device_id`.

### profile_create

Create a new device profile. In addition to the base fields, the tool
accepts the pre-boot record fields used by EK-bound config delivery and
remote UKI signing: `ek_serial`, `ek_cert` (PEM; must parse as an X.509
certificate), `mac_address`, `config` (full merged platform config
object), `assigned`, and `assigned_at` (RFC3339), plus `tls_server_name`
(the certificate name the attestation collector verifies a node of this
profile against; empty means the device FQDN).

```json
{
  "name": "profile_create",
  "description": "Create a new device profile with network configuration and matching rules",
  "inputSchema": {
    "type": "object",
    "properties": {
      "name": {"type": "string"},
      "model": {"type": "string"},
      "role": {"type": "string"},
      "zone": {"type": "string"},
      "networks": {"type": "object"},
      "match_rules": {"type": "object"},
      "ek_serial": {"type": "string"},
      "ek_cert": {"type": "string", "description": "Prestaged PEM EK certificate"},
      "mac_address": {"type": "string"},
      "config": {"type": "object"},
      "assigned": {"type": "boolean"},
      "assigned_at": {"type": "string"},
      "tls_server_name": {"type": "string"}
    },
    "required": ["name"]
  }
}
```

Results render the profile in its domain JSON shape with the uint64 `id`
as a decimal string (JSON numbers lose precision past 2^53). The
prestaged `ek_cert` is echoed back — it is public key material — so
operators can audit what is prestaged. The result also carries the
read-only `pcr_baseline` when one is recorded; a `pcr_baseline` argument
is not part of either write tool's schema and is dropped by the typed
decode, never stored (`docs/device/api.md` §3.6).

### profile_get_by_id

Get profile by ID. A missing profile is `NotFound` here and from
`profile_delete_by_id`, as on gRPC, so the SDK reports the same error on
every transport.

```json
{
  "name": "profile_get_by_id",
  "description": "Get profile details by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Profile ID"}
    },
    "required": ["id"]
  }
}
```

### profile_update_by_id

Update profile properties by ID. Partial update: only supplied fields
replace stored values. Accepts the same pre-boot record fields as
`profile_create` (`ek_serial`, `ek_cert`, `mac_address`, `config`,
`assigned`, `assigned_at`, `tls_server_name`); an unparseable `ek_cert` is
rejected with a typed validation error. An omitted (or `null`)
`tls_server_name` keeps the stored name, and an explicit `""` clears it, so
the collector verifies each node against its own FQDN again
(`docs/device/api.md` §3.2).

```json
{
  "name": "profile_update_by_id",
  "description": "Update profile properties by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer"},
      "name": {"type": "string"},
      "model": {"type": "string"},
      "role": {"type": "string"},
      "ek_serial": {"type": "string"},
      "ek_cert": {"type": "string"},
      "mac_address": {"type": "string"},
      "config": {"type": "object"},
      "assigned": {"type": "boolean"},
      "assigned_at": {"type": "string"},
      "tls_server_name": {"type": "string"}
    },
    "required": ["id"]
  }
}
```

### profile_delete_by_id

Delete profile.

```json
{
  "name": "profile_delete_by_id",
  "description": "Delete a profile by ID",
  "inputSchema": {
    "type": "object",
    "properties": {
      "id": {"type": "integer", "description": "Profile ID"}
    },
    "required": ["id"]
  }
}
```

### profile_list_all

List profiles with pagination.

```json
{
  "name": "profile_list_all",
  "description": "List all profiles with optional pagination",
  "inputSchema": {
    "type": "object",
    "properties": {
      "page": {"type": "integer", "default": 1},
      "page_size": {"type": "integer", "default": 50}
    }
  }
}
```

### profile_find_matching

Find the profile whose match rules fit a device's MAC address, serial or
model; the SDK's `FindMatchingProfile` uses it on this transport. At least
one attribute is required (`InvalidArgument` otherwise), and no matching
profile is `NotFound`, as on gRPC. Requires `device:read`. The result is
the profile in its domain JSON shape.

```json
{
  "name": "profile_find_matching",
  "description": "Find profile matching device attributes",
  "inputSchema": {
    "type": "object",
    "properties": {
      "mac_address": {"type": "string"},
      "serial": {"type": "string"},
      "model": {"type": "string"}
    }
  }
}
```

### profile_find_by_mac

Find the profile whose `mac_prefix` rule is a prefix of a device MAC address
(compared case-insensitively); the SDK's `FindProfileByMACAddress` uses it on
this transport. A missing `mac_address` is `InvalidArgument`, and no matching
profile is `NotFound`, as on gRPC. Requires `device:read`. The result is the
profile in its domain JSON shape.

```json
{
  "name": "profile_find_by_mac",
  "description": "Find the profile whose MAC prefix rule fits a device MAC address",
  "inputSchema": {
    "type": "object",
    "properties": {
      "mac_address": {"type": "string", "description": "Device MAC address"}
    },
    "required": ["mac_address"]
  }
}
```

### profile_find_by_serial

Find the profile whose `serial_prefix` rule is a prefix of a device serial
number (compared case-insensitively); the SDK's `FindProfileBySerial` uses it
on this transport. A missing `serial` is `InvalidArgument`, and no matching
profile is `NotFound`, as on gRPC. Requires `device:read`. The result is the
profile in its domain JSON shape.

```json
{
  "name": "profile_find_by_serial",
  "description": "Find the profile whose serial prefix rule fits a device serial number",
  "inputSchema": {
    "type": "object",
    "properties": {
      "serial": {"type": "string", "description": "Device serial number"}
    },
    "required": ["serial"]
  }
}
```

### profile_assign_to_device

Binds a profile to a specific device identity — a registered device
(`device_id`; the server derives the EK serial from its stored EK certificate
and prestages it, #463) and/or an explicit TPM EK certificate serial / MAC
address — optionally prestaging the device's PEM-encoded EK certificate, and
marks the profile assigned. The EK certificate is source-agnostic: it may
come from a swtpm-backed vTPM or a physical hardware TPM. `profile_id` is
required, plus at least one of `device_id`, `ek_serial` or `mac_address`;
explicit values win over what `device_id` derives.

```json
{
  "name": "profile_assign_to_device",
  "arguments": {"profile_id": 12345, "device_id": 970392025956353}
}
```

```json
{
  "name": "profile_assign_to_device",
  "arguments": {
    "profile_id": 12345,
    "ek_serial": "1234567890",
    "mac_address": "00:25:90:ff:aa:02",
    "ek_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }
}
```

Returns the updated profile with the uint64 `id` rendered as a decimal
string.

### profile_unassign_from_device

Clears a profile's device binding: the EK serial, MAC address,
prestaged EK certificate, and assignment state are all reset.

```json
{
  "name": "profile_unassign_from_device",
  "arguments": {
    "profile_id": 12345
  }
}
```

Returns the updated (now unassigned) profile.

### device_template_create

Stores a device template — a reusable configuration, role and match rules
that profiles are built from (`DeviceService.CreateTemplate`). It is not a
vTPM template; the `vtpm_*` tools create those. `name` is required; `role`
is the domain role string ([api.md §4.2](api.md#42-role-vocabulary)) and
`config` is YAML **text**. Requires `device:write`.

```json
{
  "name": "device_template_create",
  "arguments": {
    "tenant_id": "acme",
    "name": "edge",
    "role": "load-balancer",
    "config": "hostname: edge-01\n",
    "match_rules": {"mac_prefix": "00:25:90"}
  }
}
```

Returns the stored template with the server-assigned `id` as a decimal
string and `config` as text.

### profile_create_from_template

Builds a profile from a stored device template and saves it
(`DeviceService.CreateProfileFromTemplate`). `template_id` is required. The
profile takes the template's tenant, role, config and match rules; the
non-empty fields of `overrides`, which use the `profile_create` argument
names, replace them. Requires `device:write`.

```json
{
  "name": "profile_create_from_template",
  "arguments": {
    "template_id": 9000,
    "overrides": {"name": "gw-01", "ek_serial": "1234567890"}
  }
}
```

Returns the saved profile with the uint64 `id` rendered as a decimal
string. The Go SDK refuses template `bmc` and `overrides.tenant_id`,
`overrides.networks` and `overrides.platformd_config` before sending, since
these arguments have no place for them ([api.md §4](api.md#4-device-templates)).

## Resources

### device://inventory

Read-only access to device inventory.

```json
{
  "uri": "device://inventory",
  "name": "Device Inventory",
  "description": "Complete device inventory with status",
  "mimeType": "application/json"
}
```

### device://profiles

Read-only access to device profiles.

```json
{
  "uri": "device://profiles",
  "name": "Device Profiles",
  "description": "All configured device profiles",
  "mimeType": "application/json"
}
```

### device://{id}

Individual device resource.

```json
{
  "uri": "device://{id}",
  "name": "Device Details",
  "description": "Device details by ID",
  "mimeType": "application/json"
}
```

## Usage Examples

### stdio Mode

```bash
# Start MCP server
platformctl mcp serve --transport stdio

# Example tool call (sent via stdin)
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "device_list",
    "arguments": {"page": 1, "page_size": 10}
  }
}
```

### HTTP Mode

```bash
# Start MCP server
platformctl mcp serve --transport http --port 9445

# Tool call over HTTPS (TLS 1.3 only; trust the platform CA)
curl --tlsv1.3 --cacert platform-ca.pem -X POST https://localhost:9445/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "device_get",
      "arguments": {"id": 1234567890}
    }
  }'
```

### Response Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"id\":1234567890,\"serial\":\"SRV-2024-001\",\"model\":\"TrustedServer-v2\"}"
      }
    ]
  }
}
```

## Error Handling

MCP errors follow JSON-RPC 2.0. A failed tool call answers the code for its
error class (#505); the message is the error text and `data` names the tool:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32005,
    "message": "DEVICE_NOT_FOUND: device not found",
    "data": "device_get"
  }
}
```

| Code | Description |
|------|-------------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid argument (also an unknown tool) |
| -32001 / -32002 / -32003 | Authentication required / invalid token / permission denied |
| -32004 | Service unavailable |
| -32005 | Not found |
| -32006 | Already exists |
| -32007 | Failed precondition |
| -32603 | Unclassified failure |

The classification rules are in [`docs/daemon/api.md`](../daemon/api.md) §1.

See [api-reference.md](api-reference.md) for complete error code mapping.
