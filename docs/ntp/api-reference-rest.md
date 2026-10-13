# NTP REST API Reference

> **Status: ARCHIVE — historical record. Do NOT build from this document.**
> Last verified: 2026-10-13 · Replaced by [api.md](api.md) (§8). The two listeners do not return the same response body: the webservice wraps the message in an envelope and the daemon listener does not ([api.md](api.md) §2).

| Property | Value |
|----------|-------|
| Endpoint | `https://host:8443` (webservice) |
| Base path | `/api/v1/ntp` |
| Routers | `pkg/webservice/v1/rest/ntp/router.go` (webservice), `pkg/api/rest/ntp_handlers.go` (daemon REST listener) |
| Encoding | protobuf JSON (`protojson`, camelCase + snake_case accepted) |

Both listeners mount identical paths and delegate to the same
in-process `platform.v1.NTPService` implementation, so a client sees the
same responses regardless of which REST server it reaches. The
webservice wraps payloads in the standard
`{"code","success","error","payload"}` envelope; the daemon listener
returns the bare message. The SDK REST adapter handles both. The daemon
listener enforces the scope below on every route (401 without a credential,
403 without the scope); see [api.md](api.md) §6.

## Endpoints

| Method | Path | Operation | Scope |
|--------|------|-----------|-------|
| `GET` | `/api/v1/ntp/status` | GetStatus | `ntp:read` |
| `GET` | `/api/v1/ntp/sources` | ListSources | `ntp:read` |
| `POST` | `/api/v1/ntp/step` | Step | `ntp:write` |

None of the operations take request parameters.

## GET /api/v1/ntp/status

```json
{
  "status": {
    "synced": true,
    "stratum": 3,
    "leapStatus": "Normal",
    "offsetSeconds": -0.000012,
    "rootDispersion": 0.045,
    "rootDelay": 0.023,
    "lastSyncUnix": "1755000000",
    "mode": "both",
    "referenceId": "CB00710F",
    "referenceName": "10.4.6.1",
    "sourcesReachable": 1,
    "sourcesTotal": 2,
    "anomaly": false,
    "anomalyReason": "",
    "serveNameFindings": []
  }
}
```

`lastSyncUnix` is `0` when the node has never synchronized.

`serveNameFindings` is absent on a correctly configured node. An entry means
this node advertises an NTS-KE name clients cannot usefully dial (#509), and
`kind` says which of the two ways:

```json
{
  "kind": "nts-name-unreachable",
  "name": "cp.example.internal",
  "address": "10.4.2.140",
  "listenNetworks": ["10.4.6.0/24", "192.0.2.0/24"]
}
```

```json
{
  "kind": "nts-name-unresolvable",
  "name": "time.example.internal",
  "error": "lookup time.example.internal: no such host"
}
```

`address` and `listenNetworks` are absent on an unresolvable finding: it has
no address, so it makes no claim about the allow list. Neither kind says
anything about this node's own clock — `synced` can be `true` beside either.

## GET /api/v1/ntp/sources

```json
{
  "sources": [
    {
      "address": "10.4.6.1",
      "mode": "server",
      "state": "selected",
      "stratum": 2,
      "pollSeconds": 64,
      "reach": 377,
      "lastRxSeconds": "23",
      "offsetSeconds": -0.000021,
      "reachable": true
    }
  ]
}
```

`state` is one of `selected`, `combined`, `excluded`, `unreachable`,
`falseticker`, `jittery`, `unknown`. `reach` is chrony's 8-bit
reachability register: `255` means the last eight polls all succeeded.

## POST /api/v1/ntp/step

Forces an immediate clock correction and returns the resulting status
in the same shape as `GET /status`.

## Status Codes

| Code | Condition |
|------|-----------|
| `200` | Success |
| `409` | `Step` requested with no reachable source — the clock is not moved on stale data |
| `500` | Malformed control-socket output |
| `503` | No `ntp:` section configured, or chrony's control socket is unreachable |
| `504` | The operation exceeded its deadline |

## Example

```sh
curl --cacert ca.pem https://cp.example.com:8443/api/v1/ntp/status
curl --cacert ca.pem -X POST https://cp.example.com:8443/api/v1/ntp/step
```
