# IAM — CLI

> **Status: NORMATIVE** · Scope: `platformctl iam` · Last verified: 2026-10-17
> Conflicts with this document are defects. Fix them here first.
> Read out of `pkg/cli/commands/iam/` on 2026-08-18.

---

## 1. Command group

```
platformctl iam
    user     Manage users
    group    Manage groups
    role     Manage roles
    policy      Manage authorization policies
    permission  Check IAM permissions
    app      Manage OAuth applications
```

**Every verb is tenant-explicit.** `get`, `delete` and the role verbs take
`<tenant-id>` as a **positional argument**; `create`, `update` and `list` take
`--tenant` (required). That is deliberate: it makes the ambiguity the REST
surface has — where an unscoped route's tenant comes from context — impossible
at the CLI.

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:125`), precedence
**flag > environment > config file > default**:

| Flag | Short | Default | Environment |
|---|---|---|---|
| `--config` | `-c` | platform default | `PLATFORMCTL_CONFIG` |
| `--context` | | current-context | `PLATFORMCTL_CONTEXT` |
| `--transport` | | from context | `PLATFORMCTL_TRANSPORT` |
| `--server` | | from context | `PLATFORMCTL_SERVER` |
| `--server-name` | | | `PLATFORMCTL_SERVER_NAME` |
| `--output` | `-o` | `table` | `PLATFORMCTL_OUTPUT` |
| `--verbose` | `-v` | `false` | |
| `--no-color` | | `false` | `NO_COLOR` |

`iam group` binds `-t` to `--tenant`, `-n` to `--name` and `-d` to
`--description`. The other subgroups use long-form `--tenant` with no short.
**That inconsistency is in the code**; use long forms.

---

## 2. `platformctl iam user`

| Verb | Positional | Flags |
|---|---|---|
| `create` | — | `--tenant` (required), `--email` (required), `--name`, `--roles`, `--groups`, `--attributes` |
| `get` | `<tenant-id> <user-id>` | — |
| `list` | — | `--tenant` (required), `--page`/`-p` (default 1), `--page-size`/`-s` (default 50) |
| `update` | — | `--tenant` (required), `--user-id` (required), `--email`, `--name`, `--roles`, `--groups`, `--attributes` |
| `delete` | `<tenant-id> <user-id>` | — |
| `assign-role` | `<tenant-id> <user-id> <role>` | — |
| `revoke-role` | `<tenant-id> <user-id> <role>` | — |

**`update` replaces rather than merges.** The help text says so explicitly for
`--roles`, `--groups` and `--attributes`: *"(replaces existing)"*. Passing
`--roles admin` on a user who had `admin,operator` leaves them with `admin`
alone. To add a role, use `assign-role`.

`--attributes` is comma-separated `key=value` pairs.

```bash
platformctl iam user create --tenant tenant-a --email ops@example.com \
    --name "Ops" --roles operator --groups platform-ops
platformctl iam user get tenant-a u-0f21
platformctl iam user assign-role tenant-a u-0f21 admin
platformctl iam user revoke-role tenant-a u-0f21 admin
```

---

## 3. `platformctl iam group`

| Verb | Positional | Flags |
|---|---|---|
| `create` | `<group-id>` | `--tenant`/`-t` (required), `--name`/`-n`, `--description`/`-d` |
| `get` | `<tenant-id> <group-id>` | — |
| `list` | — | `--tenant`/`-t` (required), `--page`/`-p` (default 1), `--page-size`/`-s` (default 50) |
| `update` | `<group-id>` | `--tenant`/`-t` (required), `--name`/`-n`, `--description`/`-d` |
| `delete` | `<tenant-id> <group-id>` | — |
| `add-member` | `<tenant-id> <group-id> <user-id>` | — |
| `remove-member` | `<tenant-id> <group-id> <user-id>` | — |

`add-member` and `remove-member` call the IAM `AddGroupMember` and
`RemoveGroupMember` RPCs and return the daemon's error unchanged. With
`--output json` they print `{"success": true, "message": "..."}`.

```bash
platformctl iam group add-member    tenant-a g-01 u-0f21
platformctl iam group remove-member tenant-a g-01 u-0f21
```

`iam user update --groups ...` also sets a user's group list, but it
**replaces** the list.

---

## 4. `platformctl iam role`

| Verb | Positional | Flags |
|---|---|---|
| `create` | `<role-id>` | `--tenant` (required) |
| `get` | `<tenant-id> <role-id>` | — |
| `list` | — | `--tenant` (required), `--page`/`-p` (default 1), `--page-size`/`-s` (default 50) |
| `update` | `<role-id>` | `--tenant` (required) |
| `delete` | `<tenant-id> <role-id>` | — |

---

## 5. `platformctl iam policy`

| Verb | Positional | Purpose |
|---|---|---|
| `create` | — | Create a policy |
| `get` | `<tenant-id> <policy-name>` | Policy information |
| `list` | — | List policies |
| `update` | — | Update a policy |
| `delete` | `<tenant-id> <policy-name>` | Delete a policy |
| **`validate`** | — | Validate a policy YAML file |
| **`test`** | — | Test a policy against a request |

**`validate` and `test` are the two verbs to use before `create`.** `validate`
checks the YAML is a well-formed policy; `test` evaluates it against a concrete
request and tells you what it would decide. Applying an authorization policy
without testing it is how a lockout happens.

```bash
platformctl iam policy validate --tenant tenant-a ...
platformctl iam policy test     --tenant tenant-a ...
platformctl iam policy create   --tenant tenant-a ...
```

---

## 6. `platformctl iam permission`

| Verb | Positional | Flags |
|---|---|---|
| `check` | — | `--tenant` (required), `--subject` (required), `--action` (required), `--resource` (required), `--roles`, `--groups`, `--context`, `--attributes` |

`check` calls the IAM `CheckPermission` RPC. It asks whether the subject may
perform the action on the resource. `--roles` and `--groups` are
comma-separated IDs. `--context` and `--attributes` are comma-separated
`key=value` pairs. `--output json` prints `allowed`, `matched_policy`,
`matched_rule`, `reason` and `evaluation_time_ns`. `allowed` is always present.

```bash
platformctl iam permission check --tenant tenant-a --subject u-0f21 \
    --roles operator --action read --resource users -o json
```

The daemon answers through its policy enforcement point (`pepClient.Check`
in `pkg/api/daemon/iam_grpc_service.go`).

---

## 7. `platformctl iam app`

OAuth applications.

| Verb | Positional | Flags |
|---|---|---|
| `register` | — | `--tenant` (required), `--name` (required), `--redirect-uris`, `--grant-types` (default `authorization_code`), `--response-types` (default `code`), `--resource-prefix` |
| `get` | `<tenant-id> <client-id>` | — |
| `list` | — | `--tenant` (required) |
| `update` | — | `--tenant` (required), `--client-id` (required), plus the same optional flags |
| `delete` | `<tenant-id> <client-id>` | — |
| `rotate-secret` | `<tenant-id> <client-id>` | — |

`--grant-types` defaults to `authorization_code` and `--response-types` to
`code` — the modern, safest OAuth defaults. Widening them is a decision worth
recording.

**`rotate-secret` prints a credential.** Treat the output accordingly; there is
no "get secret" verb, deliberately, so rotation is the only way to obtain one and
the old value stops working.

```bash
platformctl iam app register --tenant tenant-a --name "Ops Console" \
    --redirect-uris https://console.example.com/callback
platformctl iam app rotate-secret tenant-a c-9a3f
```

---

## 8. What the CLI does not cover

| Capability | Reach it with |
|---|---|
| Authenticate | gRPC, QUIC, MCP |
| Create / verify / revoke a token | gRPC, QUIC (`0xF9`–`0xFB`), MCP |
| Tenant CRUD (IAM scoping) | REST `/api/v1/iam/tenants`, gRPC, MCP |

Platform tenancy — the VLAN/bridge/keyspace/DEK kind — is a different feature
with its own CLI: `platformctl tenant` ([`docs/tenant/`](../tenant/)).

---

## 9. Parity gap

`conventions/feature-docs.md` §4 requires every verb here to have a
`CommandDefinition` in the integration parity suite. **No `CommandDefinition`
type exists in this repository** (grepped 2026-08-18), so the requirement is
unmet repo-wide. Raised as an owner question in the migration report.
