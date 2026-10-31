# DNS — CLI

> **Status: NORMATIVE** · Scope: DNS verbs in `platformctl` · Last verified: 2026-10-26
> Conflicts with this document are defects. Fix them here first.

---

## The `platformctl dns` group

`platformctl dns` (`pkg/cli/commands/dns/`) drives the `DNSService` through the
SDK client. It works on any transport chosen with `--transport`. Each verb
calls exactly one RPC from `pkg/api/grpc/proto/platform_dns.proto`. The only
exception is `record get`, described below.

```
platformctl dns
├── zone     create | get | update | delete | list
├── record   add | update | delete | list | get
├── dnssec   sign | status
├── resolve  <fqdn>
└── register <fqdn> <ip>
```

Global flags apply as usual: `--config`, `--transport`, and `-o table|json|yaml`.
`table` is a human summary. `json` and `yaml` print the RPC's response
message in protojson form with proto field names (`zone_name`, `soa`,
`ds_records`). The REST and gRPC references therefore describe the same
document ([api.md](api.md)).

---

## Zones

| Verb | RPC | Flags |
|---|---|---|
| `zone create <zone>` | `CreateZone` | `--ttl` (3600), `--description`, `--internal`, `--ns` (repeatable), `--soa-mname`, `--soa-rname`, `--soa-serial` (1), `--soa-refresh` (86400), `--soa-retry` (7200), `--soa-expire` (86400), `--soa-minimum-ttl` (3600) |
| `zone get <zone>` | `GetZone` | — |
| `zone update <zone>` | `UpdateZone` | `--ttl`, `--description` |
| `zone delete <zone>` | `DeleteZone` | — |
| `zone list` | `ListZones` | `--internal-only` \| `--public-only`, `--page`, `--page-size` |

`zone create` sends an SOA only when `--soa-mname` or `--soa-rname` is set.
Without either, the server writes its own SOA. `--internal-only` and
`--public-only` cannot be combined. Pagination is sent only when `--page` or
`--page-size` is greater than zero.

```sh
platformctl dns zone create example.test. --soa-mname ns1.example.test. \
    --soa-rname hostmaster.example.test. --ns ns1.example.test.
platformctl dns zone list --internal-only -o json
```

---

## Records

| Verb | RPC | Flags |
|---|---|---|
| `record add <zone>` | `AddRecord` | `--type`, `--name`, `--value`, `--ttl` (3600), plus the type's fields below |
| `record update <zone>` | `UpdateRecord` | as `add`; the record of that type and name is replaced |
| `record delete <zone>` | `DeleteRecord` | `--type`, `--name` |
| `record list <zone>` | `ListRecords` | `--type`, `--page`, `--page-size` |
| `record get <zone>` | `ListRecords` | `--type`, `--name` |

`--type` is case-insensitive. The writable types and the fields each one
takes:

| Type | `--value` holds | Extra flags |
|---|---|---|
| A, AAAA | address | — |
| CNAME, NS | target name | — |
| TXT | text | — |
| MX | exchange | `--priority` |
| SRV | target | `--priority`, `--weight`, `--port` |
| CAA | value | `--flags`, `--tag` |
| TLSA | certificate data (hex) | `--usage`, `--selector`, `--matching-type` |

SOA, DNSKEY, DS, RRSIG and the NSEC family are produced by the server (zone
creation and `dnssec sign`). Writing one returns `ErrRecordTypeNotWritable`.
These types can still be read with `record list --type`.

The proto has no single-record read, so `record get` lists the zone's records
of `--type` and keeps the ones named `--name`. If none match, it returns
`ErrRecordNotFound`.

```sh
platformctl dns record add example.test. --type a --name www --value 192.0.2.10
platformctl dns record add example.test. --type srv --name _sip._tcp \
    --value sip.example.test. --priority 10 --weight 5 --port 5060
platformctl dns record get example.test. --type a --name www -o yaml
```

---

## DNSSEC, resolution and registration

| Verb | RPC | Output |
|---|---|---|
| `dnssec sign <zone>` | `SignZone` | the signed zone |
| `dnssec status <zone>` | `GetDNSSECStatus` | enabled, signed, algorithm, key size, key count, one `ds` row per DS (`keytag alg digest-type digest`) |
| `resolve <fqdn> [--type]` | `Resolve` | matching records. Without `--type`, every type is returned |
| `register <fqdn> <ip>` | `Register` | the zone the address was registered in |

`dnssec status` is where the parent-zone DS records come from
([dnssec.md](dnssec.md)).

---

## Transport coverage

The CLI never chooses a transport per verb. A verb fails on a transport that
does not carry its RPC, and the transport returns the error ([api.md](api.md) §2):

| Verb | Not carried by |
|---|---|
| `zone get`, `record update`, `dnssec sign`, `dnssec status`, `register` | QUIC (the SDK QUIC adapter maps only add, delete and list record, resolve, and zone create, update, delete and list: `sdk/go/transport/quic/adapter.go:879-886`) |

Every other verb works on all transports. REST carries every verb.

---

## Errors

Flag and argument errors come back as typed errors before any RPC is sent:
`ErrUnknownRecordType`, `ErrRecordTypeNotWritable`, `ErrFlagRequired`. A failed
RPC is wrapped in `WrappedError` together with the operation and zone. A
failure to encode the `-o json|yaml` output is `ErrRenderFailed`.

---

## Adjacent CLI that touches DNS

- **ACME DNS-01 challenges**: `platformctl acme` ([`docs/ca/`](../ca/)) answers
  challenges with DNS records; see [acme-integration.md](acme-integration.md).
- **DANE**: TLSA records are published with `record add --type tlsa` or by the
  platform itself; see [dane.md](dane.md).

---

## Integration parity

The CLI leg of `test/integration/dns/` runs the same assertions as the gRPC leg.
Its adapter (`cli_adapter.go`) carries every `DNSService` RPC over these verbs
with `-o json` and decodes the protojson output.
