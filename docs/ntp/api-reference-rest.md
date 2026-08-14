# NTP REST API Reference

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
returns the bare message. The SDK REST adapter handles both.

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
    "referenceName": "198.18.0.1",
    "sourcesReachable": 1,
    "sourcesTotal": 2,
    "anomaly": false,
    "anomalyReason": ""
  }
}
```

`lastSyncUnix` is `0` when the node has never synchronized.

## GET /api/v1/ntp/sources

```json
{
  "sources": [
    {
      "address": "198.18.0.1",
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
