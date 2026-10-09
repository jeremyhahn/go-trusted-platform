# Gateway REST API Reference

Base paths are `/api/v1/gateway` for gateway state and `/api/v1/sdn/gateway`
for SDN-scoped gateway operations.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/gateway/status` | Gateway node status. |
| `POST` | `/api/v1/gateway/mode` | Deprecated compatibility mode setter. |
| `GET` | `/api/v1/gateway/state` | List reported gateway snapshots. |
| `GET` | `/api/v1/gateway/state/{gateway_id}` | Read one gateway snapshot. |
| `GET` | `/api/v1/sdn/gateway/overlay/vteps` | List admitted overlay VTEPs. Optional `gateway_id` query selects a reported gateway. |
| `GET` | `/api/v1/sdn/gateway/overlay/vteps/{vtep}` | Read one admitted overlay VTEP. Optional `gateway_id` query selects a reported gateway. |

The snapshot response includes `overlay` when the overlay service is running.
That object carries the local VTEP, table ids, admitted VTEPs and ND counters:
`punted`, `answered`, `meter_dropped`, `queue_dropped`, and `fell_through`.

An admitted-VTEP read returns not found when the address is not currently
admitted.
