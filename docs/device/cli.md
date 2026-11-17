# Device Identity, Profiles and Inventory — CLI

> **Status: NORMATIVE** · Scope: `platformctl device`, `platformctl profile` · Last verified: 2026-10-17
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> Every verb and every flag below was read out of `pkg/cli/commands/device/`
> and `pkg/cli/commands/profile/` on 2026-08-18; the profile read, delete and
> match verbs were re-read on 2026-10-13 (#460); `device update`, `device
template` and the match-rule flags were added on 2026-10-17 (#949).

---

## 1. Command groups

```
platformctl device            Device management operations
platformctl device profile    Device profile management
platformctl device template   Device template management (§2.11)
platformctl device attest-cert  The attestation certificate on a device record (§2.7)
platformctl profile           Device profile get/list/delete/match (§4)
```

Both groups are registered on the root command
(`pkg/cli/commands/root.go:186` and `:200`). `device profile` is canonical; the
top-level `profile` group mounts the same `get`, `list`, `delete` and `match`
commands (`device.NewProfileLookupCommands`), so the two trees run one
implementation and behave identically (§4).

### Global flags

`platformctl` persistent flags (`pkg/cli/commands/root.go:135`). Precedence is
**flag > environment > config file > built-in default**.

| Flag | Short | Type | Default | Environment | Meaning |
|---|---|---|---|---|---|
| `--config` | `-c` | string | platform default config path | `PLATFORMCTL_CONFIG` | Config file |
| `--context` | | string | current-context | `PLATFORMCTL_CONTEXT` | Named context to use |
| `--transport` | | string | from context | `PLATFORMCTL_TRANSPORT` | `unix`, `grpc`, `rest`, `quic`, `mcp`, `embedded` |
| `--server` | | string | from context | `PLATFORMCTL_SERVER` | Server address; implies a remote context |
| `--server-name` | | string | | `PLATFORMCTL_SERVER_NAME` | TLS SNI / certificate verification hostname |
| `--output` | `-o` | string | `table` | `PLATFORMCTL_OUTPUT` | `table`, `json`, `yaml` |
| `--verbose` | `-v` | bool | `false` | | Verbose output |
| `--no-color` | | bool | `false` | `NO_COLOR` | Disable coloured output |

An invalid `--transport` is rejected before any command runs, with
`invalid --transport %q: must be one of unix, grpc, rest, quic, mcp, embedded`.

**Which verbs work without a server.** None of them, except through the
embedded transport. Every implemented verb builds a `cli.BaseCommand` and
speaks to a `DeviceServiceClient`. `--transport embedded` runs the services
in-process and is the only way to use them with no daemon listening.
`device register` uses the selected context like every other verb.

---

## 2. `platformctl device`

| Verb | Argument | Purpose |
|---|---|---|
| `list` | — | List devices, paginated |
| `get` | `<id>` | Get a device by id |
| `find-serial` | `<serial>` | Find a device by serial number |
| `register` | — | Create a device record (`CreateDevice`) |
| `update` | `<id>` | Change a device's model and key material, §2.10 |
| `delete` | `<id>` | Delete a device by id |
| `attest` | `<id>` | Submit attestation evidence for a device, §2.6 |
| `attest-cert` | — | Sub-group (`record <id>`): the attestation certificate on a device record, §2.7 |
| `boot` | — | Sub-group (`certificate`, `delivery`), §2.8 |
| `disable` | `<id>` | Block the device's switch port and record it suspended, §2.9 |
| `enable` | `<id>` | Re-admit a disabled device to quarantine pending re-attestation, §2.9 |
| `profile` | — | Sub-group, §3 |
| `template` | — | Sub-group, §2.11 |

### 2.1 `device list`

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--page` | int | `1` | no | Page number, 1-indexed |
| `--page-size` | int | `20` | no | Items per page |

Table columns are `ID`, `SERIAL`, `MODEL`, followed by a
`Page N of M (Total: K devices)` line. `--output json` returns
`{page, page_size, total, total_pages, devices[]}`.

```bash
platformctl device list --page 2 --page-size 50
platformctl device list --output json
```

### 2.2 `device get <id>`

No local flags. `<id>` must parse as an unsigned decimal integer or the command
fails with `invalid device ID: <id>` before connecting.

Table output prints `ID`, `Serial`, `Model`, `Hash Algo`, and — when present —
truncated `EK Cert`, `Attest Pub` and `Signing`. JSON output omits the three
key fields entirely when empty.

```bash
platformctl device get 4398046511105 --output json
```

### 2.3 `device find-serial <serial>`

No local flags. An empty serial fails with `serial number is required`. A
lookup that returns no device fails with
`device not found with serial: <serial>`. Output format is identical to
`device get`.

```bash
platformctl device find-serial SRV-2024-001
```

### 2.4 `device register`

Creates a **device record** through the SDK's `CreateDevice` call and prints
the device the control plane stored, in the same format as `device get`. The
control plane assigns the id. Device profiles are a separate resource — create
one with `device profile create` (§3).

| Flag | Type | Default | Required | Meaning |
|---|---|---|---|---|
| `--serial` | string | | **yes** | Device serial number |
| `--model` | string | | no | Device model |
| `--ek-cert` | string | | no | TPM EK certificate: a PEM file path or inline PEM; must parse as X.509 |
| `--attest-pub` | string | | no | Attestation public key |
| `--attest-cert` | string | | no | PEM attestation (IAK/AK) certificate |
| `--signing-pub` | string | | no | Signing public key |
| `--hash-algo` | uint32 | `0` | no | TPM hash algorithm id (e.g. `11` for SHA-256) |

A missing `--serial` fails with `device register: --serial is required` before
connecting. A server rejection fails with
`device register: failed to create device "<serial>": <cause>` and prints
nothing.

It works over every context, REST included: the SDK REST transport posts the
proto shape `{"device": {…}}`, which both REST listeners accept
([api.md](api.md) §2.2). A serial another device already carries fails with
`AlreadyExists` on every transport.

```bash
platformctl device register --serial SN-0001 --model r640
platformctl device register --serial SN-0002 --ek-cert /var/lib/platform/ek.pem \
    --hash-algo 11 --output json
```

### 2.5 `device delete <id>`

No local flags — **there is no `--force` and no confirmation prompt.** The help
text warns that the operation is irreversible; the command does not ask.

```bash
platformctl device delete 4398046511105
```

### 2.6 `device attest <id> --evidence-file <path>`

Verifies TPM quote evidence the caller supplies against a registered device
(`AttestDevice`, [api.md](api.md)). It does not ask the device for a fresh
quote. `--evidence-file` is the JSON `DeviceQuoteEvidence` document
(`quote`, `signature`, `nonce`, `pcrs`, base64 values) every transport carries.

```bash
platformctl device attest 123 --evidence-file quote.json --output json
```

**A failed verification is not an error**: the command exits 0 and prints
`verified: false` with each check (`signature_valid`, `nonce_valid`,
`pcrs_valid`, `ak_certificate_verified`), `attestation_status` and `message`.
Checked before connecting: a non-numeric or zero id, `device attest:
--evidence-file is required`, an unreadable file (`device attest: failed to
read evidence file <path>: <reason>`) and an empty one (`device attest:
evidence file <path> is empty`). An unknown device fails with the `NOT_FOUND`
error of §2; evidence that cannot be evaluated fails with `device attest:
failed to attest device <id>: <reason>`.

### 2.7 `device attest-cert record <id> [--reissue] [--clear-on-refusal]`

Records — or re-records — the device's attestation (IAK/AK) certificate on
its platform record without re-enrolling the device ([api.md §4.5](api.md#45-recording-the-attestation-certificate-without-re-enrolling-473)).
It is the operator's step after the CA upgrade for a device enrolled before
the control plane recorded certificates (#447): the device's quotes are denied
until one is recorded.

The control plane fails closed and **the CLI has no override flag**: a
certificate is recorded only if it parses, chains to the platform CA, carries
`tcg-cap-verifiedTPMRestricted` (2.23.133.11.1.3) and certifies the device's
enrolled attestation key. Anything else is refused with a message naming every
candidate and the reason, and by default nothing is written — an unrestricted
certificate would quarantine the device on its next quote.

`--reissue` lets the platform CA issue a fresh certificate over the device's
enrolled attestation public key when nothing stored passes. The device is not
involved. Whether the CA stamps the attribute depends on the CA's own profile
(go-xkms ≥ 0.9.3 through go-quicbaas); a re-issued certificate without it is
refused like any other and the control plane revokes it in the same call so
the CA does not accumulate non-compliant attestation certificates. If that
revocation fails, the error names the serial and subject to revoke by hand.
The CA's profile cannot be probed beforehand, so pass the flag only once the
CA is known to comply.

`--clear-on-refusal` (off by default) is for a device that already holds a
non-compliant certificate and is quarantined by every quote. When every
candidate is refused, it clears the certificate on the record instead of
leaving it, so the device's next quote is denied rather than quarantined until
a compliant certificate is recorded. It never clears a compliant certificate
and never clears on any other error. The clear is audited as
`device_attest_cert_cleared` with the refusal. If the record changes while the
call runs, nothing is written and the command fails with a conflict; re-run
it.

```bash
platformctl device attest-cert record 4398046511105
platformctl device attest-cert record 4398046511105 --reissue -o json
platformctl device attest-cert record 4398046511105 --clear-on-refusal
```

Table output leads with `Attestation certificate recorded` or `… already
recorded; nothing changed`, then ID, Serial, Model, Source (`already on the
device record` / `platform CA certificate store (<name>)` / `re-issued by the
platform CA (<cn>)`), Reissued, Subject, Certificate Serial, Not After. JSON
output is the response of §4.5 with `id` in place of `device_id`. A clear
leads with a warning, `Refused attestation certificate cleared; …`, then ID,
Serial, Model, Refusal, and the Subject, Certificate Serial and Not After of
the removed certificate (`Cleared …`); JSON has `"cleared": true` and
`"refusal"`, and the command exits zero. Any refusal that is not cleared
exits non-zero with `attestation certificate not recorded for device <id>:
<control plane message>`.

After a successful record, the attestation collector's next sweep verifies a
quote against the new certificate and the device's report changes state
([attestation/user.md](../attestation/user.md)).

### 2.8 `device boot certificate` and `device boot delivery`

Send a diskless node's two per-boot requests ([api.md §4.6](api.md#46-diskless-boot-delivery-690))
over whichever SDK transport `--transport` selects. The control plane
authenticates both itself; the proof of possession and the attestation
evidence are bound to a nonce exported from the TLS session of the connection
that carries them. The commands therefore make the proof only after they have
connected, on that connection — there is no flag that takes proof bytes
computed in advance, because such bytes cannot be for this connection.

```bash
platformctl device boot certificate --identity node-1.example --key idevid.key
platformctl device boot delivery --quote-command /usr/libexec/node-quote
```

| Flag | Command | Meaning |
|---|---|---|
| `--identity` | certificate | The claimed device identity (serial or enrollment hostname) |
| `--key` | certificate | PEM private key of that identity's IDevID: PKCS#8 (`PRIVATE KEY`), SEC 1 (`EC PRIVATE KEY`) or PKCS#1 (`RSA PRIVATE KEY`). The proof is RSA-PSS or ECDSA, so any other key type is refused |
| `--quote-command` | delivery | A program run once connected, with the connection's nonce, base64-encoded, as its only argument. It prints the `vm.QuoteEvidence` JSON over that nonce on stdout |

All three flags are required. The key is read and parsed before any connection
is made; an unreadable or non-key file exits non-zero naming the path
(`ErrBootKeyUnreadable`). A quote program that exits non-zero or prints
nothing fails the command with its stderr (`ErrBootQuoteCommandFailed`).
`--transport unix` and `--transport mcp` exit non-zero without sending anything:
those transports carry no TLS connection to bind to. A refusal from the
control plane exits non-zero with its reason. A diskless node makes the real
requests itself; the commands exist to exercise the same path by hand.

### 2.9 `device disable <id> [--reason]` and `device enable <id>`

The operator's two lifecycle transitions (#250,
[architecture.md §4.6](architecture.md#46-operator-disable-and-enable-250)).
Each is its own control-plane call — `DisableDevice` / `EnableDevice` — and
never a device update.

| Flag | Verb | Type | Default | Meaning |
|---|---|---|---|---|
| `--reason` | `disable` | string | — | Why the device is disabled; stored as `operator: <reason>` (at most 256 bytes) |

`disable` blocks the device's switch port and records it `suspended`. `enable`
re-admits the port to the quarantine zone, records the device `quarantined` and
asks the attestation collector to quote it now; only a passing verdict restores
its previous state. `enable` asks for no confirmation; neither does `disable`
— the console confirms, the CLI does not.

```bash
platformctl device disable 4398046511105 --reason "decommissioning rack 3"
platformctl device enable 4398046511105 -o json
```

Table output leads with `Device disabled` or `Device enabled; it stays
quarantined until it re-attests`, then ID, State, Previous State, Reason (when
set) and, for `enable`, Re-attestation Requested. JSON output is
`{id, state, previous_state, state_reason, reattestation_requested}` with `id`
a number. A refusal exits non-zero with `device <id> not disabled: <control
plane message>` (or `not enabled`); the control plane refuses on a daemon with
no SDN policy engine, for a device with no switch port, and for a transition
the lifecycle does not allow — the refusals are tabled in [user.md](user.md)
and [api.md §4.7](api.md#47-operator-disable-and-enable-250).

### 2.10 `device update <id>`

```bash
platformctl device update 123 --model r650
platformctl device update 123 --ek-cert /var/lib/platform/ek.pem --hash-algo 11
```

| Flag | Type | Meaning |
|---|---|---|
| `--model` | string | Device model |
| `--ek-cert` | string | TPM EK certificate: a PEM file path or inline PEM (read as §3.1 `--ek-cert`) |
| `--attest-pub` | string | Attestation public key |
| `--attest-cert` | string | PEM attestation (IAK/AK) certificate |
| `--signing-pub` | string | Signing public key |
| `--hash-algo` | uint32 | TPM hash algorithm id (`11` = SHA-256); `0` is a value, applied when the flag is given |

The command reads the device (`GetDevice`), changes only the fields whose
flags are given and stores it (`UpdateDevice`); every other field keeps its
value. The serial is the device's identity and has no flag; a lifecycle state
changes only through `disable`/`enable` (§2.9). It prints the stored device in
the `device get` shape. A non-numeric id, no change flag at all, or an
unparseable `--ek-cert` fails before connecting.

### 2.11 `platformctl device template`

A template is a profile blueprint: a role, a platform config and a match-rule
set. Six verbs ride the SDK device client over every transport:

```bash
platformctl device template create --name rack-server --role server \
  --config-file server.yaml --match-serial-prefix SN-R650-
platformctl device template get 456 --output json
platformctl device template list                      # --page 1 --page-size 20
platformctl device template update 456 --description "R650 rack servers" --role edge
platformctl device template delete 456
platformctl device template create-profile 456 --name r650-01 --ek-serial 0A1B2C
```

- `create` and `update` take `--name` (**required on `create`**:
  `device template: --name is required`), `--description`, `--role`,
  `--config-file` and the match-rule flags, all read as in §3.1.
- `update` reads the template, changes only the flagged fields and stores it;
  `UpdateTemplate` replaces the whole template, so the read keeps the rest.
  Profiles already built from the template are not changed, nor by `delete`.
- `create-profile <template-id>` builds a profile from the template. The
  profile starts from the template's role, config and match rules; `--name`,
  `--model`, `--role`, `--zone`, `--ek-serial`, `--mac`, `--ek-cert` and the
  match-rule flags override or bind it. It prints the profile as §3.6.
- `--output json` renders a template as `{id, name, description, role,
  config_bytes, match_rules}` with `id` a decimal string and empty fields
  omitted; `list` is `{page, page_size, total, total_pages, templates: [...]}`
  and the table prints `ID`, `NAME`, `ROLE`, `DESCRIPTION`, `MATCH RULES`.
- An unknown id fails with `device template: template <id> not found`, which
  satisfies `errors.Is(err, common.ErrNotFound)`; a non-numeric id fails
  before connecting.

---

## 3. `platformctl device profile`

Eight verbs: `get`, `list`, `delete`, `match`, `create`, `update`, `assign`,
`unassign`; a profile is also built from a template with `device template
create-profile` (§2.11). All ride the SDK device client over whichever transport the active
context selects — `unix`, `grpc`, `rest`, `quic`, `mcp` or `embedded` — so the
read verbs confirm a write over the transport that made it.

### 3.0 `device profile get <id>` and `device profile list`

```bash
platformctl device profile get 123
platformctl device profile get 123 --output json
platformctl device profile list                       # --page 1 --page-size 20
platformctl device profile list --page 2 --page-size 50 --output json
```

`get` renders the profile exactly as the write verbs do (§3.6). `list` prints
`ID`, `NAME`, `ROLE`, `ZONE`, `TLS SERVER NAME`, `ASSIGNED` and a page footer;
in `--output json` it is `{page, page_size, total, total_pages, profiles: [...]}`
with each item in the §3.6 shape. A non-numeric id fails with
`device profile: invalid profile ID: <id>`; a page or page size below one
fails with `device profile: invalid pagination: …` — both before connecting.
A profile that does not exist fails with `device profile: profile <id> not
found`; any other control-plane failure with `device profile: failed to get
profile <id>: <reason>`.

### 3.0a `device profile delete <id>` and `device profile match`

```bash
platformctl device profile delete 123
platformctl device profile match --mac 00:25:90:ff:aa:02
platformctl device profile match --serial SN100-XYZ --output json
platformctl device profile match --model R640
```

`delete` removes the profile and prints `Profile <id> deleted`; in
`--output json` it is `{"id": "<id>", "deleted": true}`. A non-numeric id fails
before connecting with `device profile: invalid profile ID: <id>`.

`match` finds a profile whose match rules fit the device: MAC and serial
match by prefix, model exactly, and a profile matches when any one of its
non-empty rules fits. The control plane returns the first such profile it
scans, so keep match rules disjoint ([api.md](api.md) §3). It renders the profile as §3.6. **At least
one of `--mac`, `--serial` or `--model` is required**, checked before
connecting: `device profile: at least one of --mac, --serial or --model is
required`.

**A missing profile is an error, not empty output.** `get` and `delete` on an
unknown id fail with `device profile: profile <id> not found`; `match` with no
fitting profile fails with `device profile: no profile matches mac "…",
serial "…", model "…"`. Both exit non-zero. Every transport reports the miss
as gRPC `NOT_FOUND`, and the CLI's typed errors (`ErrProfileNotFound`,
`ErrNoMatchingProfile`) satisfy `errors.Is(err, common.ErrNotFound)` from
`sdk/go/services/common`. Any other failure is
`device profile: failed to delete profile <id>: <reason>` or
`device profile: failed to match a profile: <reason>`.

### 3.0b `device profile find-config`

```bash
platformctl device profile find-config --ek-serial EK-0001
platformctl device profile find-config --mac 52:54:00:aa:bb:02 --output json
```

`find-config` returns the provisioning profile for a device's identity: the
profile whose `ek_serial` equals `--ek-serial`, else the one whose MAC address
equals `--mac` (`FindConfigForDevice`, [api.md](api.md) §3.7). It renders the
profile as §3.6. **At least one of `--ek-serial` or `--mac` is required**,
checked before connecting: `device profile: at least one of --ek-serial or
--mac is required`. No profile for the identity fails with `device profile: no
profile for ek serial "…", mac "…"` (`ErrNoConfigForDevice`, which satisfies
`errors.Is(err, common.ErrNotFound)`); any other failure is `device profile:
failed to find config: <reason>`.

### 3.1 Shared field flags (`create` and `update`)

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--name` | string | | Profile name — **required on `create`** |
| `--model` | string | | Target device model |
| `--role` | string | | `control-plane`, `gateway`, `worker`, `server`, `client`, `workstation`, `edge`, `iot`, `load-balancer` (also accepts `unknown`) |
| `--zone` | string | | Default SDN zone for this profile |
| `--ek-serial` | string | | Exact TPM EK certificate serial for boot-time identity resolution |
| `--mac` | string | | Exact MAC address for non-TPM identification |
| `--ek-cert` | string | | Prestaged EK certificate: a PEM **file path** or an inline PEM string |
| `--config-file` | string | | Device platform config, YAML or JSON; converted to JSON on the wire |
| `--tls-server-name` | string | | Certificate name the attestation collector verifies nodes of this profile against when it dials them for a quote (e.g. `compute.example.internal`); empty means the device's own FQDN (`docs/attestation/user.md`) |
| `--clear-tls-server-name` | bool | `false` | **`update` only.** Clears the stored TLS server name, so the collector verifies nodes against their own FQDN again (§3.3). Mutually exclusive with `--tls-server-name` |
| `--dice-device-id` | string | | Hex DICE device identifier (1 to 64 bytes) the registry resolves this profile by (`docs/firmware/avr-attestation.md`); lookups match it case-insensitively. An update that omits it keeps the stored value |
| `--golden-fw-hash` | string | | Hex golden firmware hash (`FWHash`, exactly 32 bytes) the device is expected to measure. An update that omits it keeps the stored value |
| `--match-mac-prefix` | string | | Match rule: MAC address prefix (e.g. `52:54:00`) |
| `--match-serial-prefix` | string | | Match rule: serial number prefix |
| `--match-model` | string | | Match rule: exact device model |

**The match-rule flags set only the rules given.** On `update` every other
stored rule keeps its value; `match` (§3.0a) and boot-time profile lookup read
them. The rendered profile carries them as `match_rules` (`Match Rules` in the
table).

**`--ek-cert` decides path-versus-inline by looking for `-----BEGIN`.** A value
containing that marker is used verbatim; anything else is treated as a file
path. Either way the result must decode as a PEM block and parse as an X.509
certificate, or the command fails with
`EK certificate is not a valid PEM x509 certificate: <reason>` — before
connecting to the server.

**`--role` is optional on create.** An empty value maps to
`DEVICE_ROLE_UNSPECIFIED` so a minimal profile stays valid.

### 3.2 `device profile create`

```bash
platformctl device profile create --name worker-01 --role client

platformctl device profile create \
    --name node-02 \
    --role server \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem \
    --config-file /etc/platform/node-02.yaml
```

### 3.3 `device profile update <id>`

Positional `<id>` required. **Only the supplied flags change**; the command
fetches the profile, applies non-empty values, and writes it back. A
non-numeric id fails with `device profile: invalid profile ID: <id>`.

```bash
platformctl device profile update 123 --ek-cert /etc/platform/ek-certs/node-02.pem
platformctl device profile update 123 --config-file /etc/platform/node-02.yaml
platformctl device profile update 123 --tls-server-name compute.example.internal
platformctl device profile update 123 --clear-tls-server-name
```

**`--tls-server-name` survives an update that omits it** twice over: this
command writes back the fetched profile with only the named flags changed,
and the server restores the stored name when an update carries none. Only
`--clear-tls-server-name` removes it: the command blanks the name and sets
`clear_tls_server_name` on the pb `UpdateProfileRequest`, the one signal the
server treats as a clear (`docs/device/api.md` §3.2). Passing it with
`--tls-server-name` fails before connecting, with cobra's mutually-exclusive
flag error naming both flags. The
same holds for the read-only `pcr_baseline` the fetched profile carries: it
travels back unchanged and the server ignores it on the way in
(`docs/device/api.md` §3.6).

### 3.4 `device profile assign <profile-id>`

Binds a profile to a device identity.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--device` | string | | Registered device id to bind to; the **control plane** derives the EK serial from the device's stored EK certificate and prestages that certificate (#463) |
| `--ek-serial` | string | | EK certificate serial identifying the device |
| `--mac` | string | | Exact MAC address identifying the device |
| `--ek-cert` | string | | Prestaged EK certificate: PEM path or inline PEM |

**At least one of `--device`, `--ek-serial` or `--mac` is required**, checked
before connecting: `device profile: assignment requires --device, --ek-serial, or --mac`.

**`--device` is resolved on the control plane, not in the CLI.** The
command sends the device id; the daemon reads the device's stored EK
certificate, derives the serial (the decimal form of the X.509 serial number)
and prestages the certificate on the profile. The CLI never parses a
certificate. A device record with no EK certificate fails with
`device <id> has no EK certificate to derive an identity from; supply ek_serial or mac_address`
(gRPC `FAILED_PRECONDITION`, surfaced as `device profile: failed to assign
profile …`). A non-numeric or zero `--device` fails before connecting with
`invalid device ID: <value>`. **Explicit flags override derived values**, not
the other way round.

Binding is what makes the attestation collector and the quote verifier find
the profile for an enrolled device: their shared resolver prefers the bound
profile, then match rules (`docs/attestation/architecture.md`). Installer
profiles have neither, so assign each enrolled device once.

```bash
platformctl device profile assign 123 --device 4398046511105
platformctl device profile assign 123 \
    --ek-serial 1234567890 \
    --mac 00:25:90:FF:AA:02 \
    --ek-cert /etc/platform/ek-certs/node-02.pem
```

### 3.5 `device profile unassign <profile-id>`

No flags. Clears EK serial, MAC, prestaged EK certificate and assignment state.

```bash
platformctl device profile unassign 123
```

### 3.6 Profile output

Every verb but `list` renders one profile. Table output prints `Profile ID`,
`Name`, and — when non-empty — `Model`, `Role`, `Zone`, `EK Serial`, `MAC`,
`EK Cert` (as `prestaged (PEM, N bytes)`), `Config` (as `N bytes (JSON)`),
`TLS Server Name`, `Match Rules`, `PCR Baseline` (as `<source> (N registers, recorded
<RFC3339>)`), and always `Assigned`. In `--output json` the same two appear as
`tls_server_name` and a `pcr_baseline` object (`values` hex by register index,
`source`, `recorded_at`, `recorded_from_device_id` as a decimal string).

**In `--output json` the profile `id` is a decimal string, not a number** —
`"id": "4398046511105"` — per the repo-wide convention for uint64 ids on the
wire. Parse it as a string.

---

## 4. `platformctl profile` — the top-level group

| Verb | Argument | Flags |
|---|---|---|
| `get` | `<id>` | — |
| `list` | — | `--page` (int, `1`), `--page-size` (int, `20`) |
| `delete` | `<id>` | — |
| `match` | — | `--mac`, `--serial`, `--model` (at least one required) |
| `find-config` | — | `--ek-serial`, `--mac` (at least one required) |

These are the `device profile` commands themselves, not copies: the group is
built from `device.NewProfileLookupCommands`. Arguments, output, errors and
transports are exactly as §3.0, §3.0a and §3.0b describe. Creating, updating,
assigning and unassigning stay under `device profile` only.

```bash
platformctl profile list --page 2 --page-size 50
platformctl profile get 123
platformctl profile delete 123
platformctl profile match --mac 00:25:90:ff:aa:02
```

---

## 5. Exit codes and output

Verbs follow the `platformctl` conventions: `0` on success, non-zero on
failure, with the structured error rendered in the selected `--output` format.
`--output json` is the form to parse; the `table` renderer is for humans and
its columns are not a stable interface.

---

## 6. Defects and gaps in this surface

**No CLI verb covers**: the separate by-MAC / by-serial profile lookups
(`match` covers both) or device activation. Reach those
through the transports in [api.md](api.md). The match-rule flags (§3.1) set
the MAC prefix, serial prefix and model rules only; the pattern, manufacturer
and TPM-vendor rules are rendered but have no flag.

**Parity gap.** `conventions/feature-docs.md` §4 requires every verb here to
have a matching `CommandDefinition` in the integration parity suite. **This
repository defines no `CommandDefinition` type** (grepped repo-wide,
2026-08-18), so the requirement is unmet repo-wide, not only for this feature.
It is recorded here rather than quietly marked satisfied.

---

## 7. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/daemon/cli.md`](../daemon/cli.md) — global flags and the `platformctl` command tree
