# Go SDK — CLI

> **Status: NORMATIVE** · Last verified: 2026-10-16
> Conflicts with this document are defects. Fix them here first.

The SDK itself has no CLI surface; platformctl consumes it. The four
application services platformd serves through the composed go-quicbaas SDK
([api.md §3.5](api.md#35-application-services-on-platformd)) each
get a platformctl group, one subcommand per RPC. The groups call the
`Client` accessors `Cache()`, `Scheduler()`, `Messaging()` and
`ObjectStorage()`, so they run on the context's transport (`--transport`):
REST, gRPC, QUIC, MCP, the Unix socket or embedded.

`-o table` prints a FIELD / VALUE table, or one row per item for a list.
Enums print without their prefix in kebab case (`one-shot`), `_unix_ms`
fields as RFC 3339 UTC times (`never` when unset), `_ms` fields as
durations, bytes as base64. `-o json` and `-o yaml` print the reply in the
proto3 JSON mapping with proto field names and every field present.

A service the node does not serve fails with `UNAVAILABLE` /
`SERVICE_NOT_CONFIGURED` (api.md §3.5). An invalid flag value fails before
any call is made.

## `platformctl cache`

| Command | RPC | Flags |
|---|---|---|
| `cache stats` | `GetStats` | `--entity-type` |
| `cache config get` | `GetConfig` | |
| `cache config set` | `UpdateConfig` | `--l1-size`, `--l1-ttl`, `--cleanup-interval`; at least one; only those given are sent |
| `cache clear` | `Clear` | exactly one of `--entity-type`, `--all` |

## `platformctl scheduler`

| Command | RPC | Flags |
|---|---|---|
| `scheduler create NAME` | `CreateJob` | `--type` (required: `one-shot`, `recurring` or `delayed`), `--handler`, `--description`, `--schedule`, `--delay`, `--execute-at` (RFC 3339), `--payload`, `--owner-type`, `--owner-id`, `--max-retries`, `--timeout`, `--tag k=v`, `--node-affinity` |
| `scheduler list` | `ListJobs` | `--status`, `--type`, `--owner-type`, `--owner-id`, `--tag k=v`, `--limit`, `--offset` |
| `scheduler get JOB_ID` | `GetJob` | |
| `scheduler update JOB_ID` | `UpdateJob` | `--name`, `--description`, `--schedule`, `--delay`, `--payload`, `--max-retries`, `--timeout`, `--tag k=v` |
| `scheduler delete JOB_ID` | `DeleteJob` | |
| `scheduler trigger` / `pause` / `resume JOB_ID` | `TriggerJob`, `PauseJob`, `ResumeJob` | |
| `scheduler cancel JOB_ID` | `CancelJob` | `--reason` |
| `scheduler history JOB_ID` | `GetJobHistory` | `--since`, `--until` (RFC 3339), `--status`, `--limit`, `--offset` |
| `scheduler status` | `GetStatus` | |

`--help` lists the accepted values of each enum flag.

## `platformctl messaging`

| Command | RPC | Flags |
|---|---|---|
| `messaging channel create NAME` | `CreateChannel` | `--codec`, `--persistent`, `--max-history`, `--buffer-size`, `--max-subscribers`, `--ttl` |
| `messaging channel list` | `ListChannels` | |
| `messaging channel get` / `delete NAME` | `GetChannel`, `DeleteChannel` | |
| `messaging channel stats NAME` | `GetChannelStats` | |
| `messaging publish CHANNEL PAYLOAD` | `Publish` | `--message-id`, `--dedup-key`, `--codec`, `--metadata k=v` |
| `messaging stats` | `GetStats` | |
| `messaging dedup-stats` | `GetDedupStats` | |

Subscribing is not offered: the streaming RPCs are not served (api.md §3.5).

## `platformctl objectstorage`

| Command | RPC | Flags |
|---|---|---|
| `objectstorage put KEY [DATA]` | `PutObject` | `--backend` (required by the service), `--file` (instead of `DATA`), `--content-type`, `--tenant`, `--shard`, `--tag k=v`, `--min-replicas`, `--replication-mode` (`sync`, `async` or `quorum`), `--replica-store`, `--archive-after-days`, `--archive-store`, `--retention-days`, `--max-versions` |
| `objectstorage get KEY` | `GetObject` | `--tenant`, `--metadata` |
| `objectstorage delete KEY` | `DeleteObject` | `--tenant` |
| `objectstorage head KEY` | `HeadObject` | `--tenant` |
| `objectstorage list` | `ListObjects` | `--prefix`, `--tenant`, `--tags`, `--limit`, `--cursor` |
| `objectstorage copy SOURCE DESTINATION` | `CopyObject` | `--backend` (required by the service), `--tenant`, `--overwrite` |
| `objectstorage list-by-tag TAG VALUE` | `ListObjectsByTag` | `--tenant`, `--limit`, `--cursor` |
| `objectstorage list-tenant TENANT` | `ListTenantObjects` | `--tags`, `--limit`, `--cursor` |

Keys take the form `namespace:path`. A list prints one row per object (`KEY`,
`SIZE`, `CONTENT TYPE`, `VERSION`, `STATUS`, `MODIFIED AT`); pass the reply's
`next_cursor` to `--cursor` for the next page. A put or copy without
`--backend` fails `INVALID_ARGUMENT`: the pinned go-quicbaas object store has
no primary backend to choose
([../objectstorage/api-reference.md](../objectstorage/api-reference.md#limits-of-the-pinned-sdk)).
