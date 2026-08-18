# Firmware Trust — API

> **Status: NORMATIVE** · Scope: firmware-trust capabilities on every transport · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).
>
> One row per capability across all six transports. A transport that does not
> carry a capability is written `MISSING — docs/13 G7`, never omitted.

---

## 1. The six transports

`sdk/go/protocol.go` declares six: `ProtocolEmbedded`, `ProtocolUnix`,
`ProtocolGRPC`, `ProtocolREST`, `ProtocolQUIC`, `ProtocolMCP`. **Unix is gRPC
over a Unix domain socket**, so gRPC and Unix share a column. The transport
model, the frame constants and the canonical QUIC category-opcode table live in
[`docs/daemon/api.md`](../daemon/api.md) and are not repeated here.

**Read this section before the tables.** Firmware trust is overwhelmingly a
*local* capability, and that is a design decision, not an oversight
([architecture.md](architecture.md) §3): a call that writes a Platform Key writes
it into the firmware of the machine executing the call, so exposing it as an RPC
would create a remote-brick primitive with no physical-presence requirement.

Exactly **one** capability in this feature is a service, and it is the one that
genuinely has to cross a host boundary: signing a digest with the control-plane
Secure Boot DB key so the node never holds the private key. That capability is
complete on all six transports. Everything else is an embedded Go call, reached
from the CLI verbs in [cli.md](cli.md).

Where a row is `MISSING`, read it as "there is no service surface here", and
then read the note under the table saying whether that is deliberate.

---

## 2. Remote Secure Boot DB signing — the one capability on all six transports

Owned by config delivery (`pkg/provisioning/configdelivery`) and documented in
full in [`docs/provisioning/`](../provisioning/); reproduced here because it is
the network half of Secure Boot.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Sign a UKI / kernel-module digest with the CP DB key | `POST /api/v1/provisioning/sign` | `ConfigDeliveryService.SignDigest` | `OpProvisioningCategory` (`0xCF`) + sub `ProvisioningSubSignDigest` (`0x03`) | `provision_sign_digest` | ✅ `ServiceRegistry.ConfigDelivery` |
| Issue the single-use nonce the sign request needs | `GET /api/v1/provisioning/config/nonce` | `ConfigDeliveryService.GetNonce` | `0xCF` + `ProvisioningSubGetNonce` (`0x01`) | `provision_get_nonce` | ✅ |

Complete on all six. The remaining config-delivery capabilities
(`FetchConfig`, session poll/fulfil/list/get, sub-opcodes `0x02`, `0x04`–`0x07`,
tools `provision_fetch_config`, `provision_poll_session`,
`provision_fulfill_session`, `provision_list_sessions`,
`provision_get_session`) belong to provisioning, not to this feature.

### Request / response

`configdelivery.SignRequest` → `configdelivery.SignResponse`:

| Field | Direction | Meaning |
|---|---|---|
| `ek_serial` | in | TPM Endorsement Key serial; at least one of this or `mac_address` is required |
| `mac_address` | in | Device MAC; the other half of the identity pair |
| `eab_key_id` | in | External Account Binding key id — **required** |
| `eab_hmac` | in | EAB HMAC over the request — **required** |
| `nonce` | in | Single-use anti-replay nonce — **required** |
| `ek_cert` | in | Base64 EK certificate; required when the matched profile is EK-bound |
| `digest` | in | The pre-computed Authenticode (or module) digest — **required, non-empty** |
| `key_ref` | in | Key selector; empty defaults to `db`. Only `db` is accepted |
| `signature` | out | Detached signature over the digest |
| `cert_pem` | out | PEM DB certificate to embed in the PE and enroll into firmware |

### Authorization

This endpoint runs **before** the node has an IDevID, so it cannot use the
platform's normal `scp`-claim path. It authenticates instead with, in order:

1. a single-use nonce, consumed before anything else;
2. an EAB credential (`eab_key_id` + `eab_hmac`);
3. a device-profile match on `ek_serial` / `mac_address`;
4. cryptographic EK-certificate binding against the matched profile.

All four are enforced **before the digest is signed**. There is no `scp`
permission on the REST route and no MCP permission entry for
`provision_sign_digest` — `AuthorizeTool` allows a tool absent from the
authorization map once the token validates, so on MCP this capability is gated
by the token and by the four checks above, not by a scope. Recorded here so the
gap is visible rather than assumed.

Post-install the node stops using this endpoint and reaches the KMS directly:
`install uki-rebuild` calls the platform `KeyManagementService.Sign` RPC over its
IDevID-authenticated mTLS client with `PreHashed: true`, and fetches the DB
certificate through `CAService.GetCertificate`.

### Errors

| Condition | Error |
|---|---|
| No DB signer wired into the control plane | `ErrSignerUnavailable` |
| Missing `eab_key_id` / `eab_hmac` / identity / digest | `ErrInvalidRequest{Reason}` |
| Missing nonce | `ErrNonceRequired` |
| Nonce consumed or EAB invalid | EAB/nonce verification error |
| No device profile matched | `ErrRemoteSignNotConfigured{"no device profile matched the request identity"}` |
| EK certificate absent or mismatched | EK-binding error |
| Secure Boot disabled / resign-mode not `remote` / no `db.key-uri` / selector other than `db` | `ErrRemoteSignNotConfigured{Reason}` |
| KMS refused the signature | `ErrSignFailed{Cause}` |
| DB certificate unavailable | `ErrCertUnavailable{Cause}` |
| Profile service missing | `ErrMissingProfileService` |

Status mapping follows the platform vocabulary in
[`docs/daemon/api.md`](../daemon/api.md) §4: invalid request → `0x01` / 400,
not-configured → `0x02` / 404, unavailable → `0x0A` / 503, internal → `0x04` / 500.

Pagination does not apply — the result set is a single signature.

---

## 3. Firmware state and enrollment

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Read firmware Secure Boot state (efivarfs) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.ReadSecureBootStatus()` / `ReadSecureBootStatusFromDir(dir)` |
| Report Setup Mode | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.IsSetupMode()` |
| Report Secure Boot enforced | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.SecureBootEnabled()` |
| Report efivarfs availability | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.EfivarsAvailable()` / `firmware.IsAvailable()` |
| Enroll PK/KEK/db into live firmware | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.EnrollKeysToEfivars(...)` / `...Dir(...)` |
| Verify a signed UKI against the db certificate | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.VerifySignedUKI(...)` |
| Enroll PK/KEK/db into an OVMF NVRAM file | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uefi.NewSecureBootEnroller(...).EnrollKeys(ctx)` |
| Read OVMF enrollment status | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*uefi.SecureBootEnroller).GetEnrollmentStatus()` |
| Read / write an arbitrary EFI variable | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `firmware.ReadVariable` / `WriteVariable` / `DeleteVariable` / `ListVariables` / `GetVariable` / `SetVariable` |
| Set / read the `TRUSTED_PLATFORM` marker | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `firmware.SetTrustedPlatform` / `ClearTrustedPlatform` / `GetTrustedPlatform` / `IsTrustedPlatform`; also `(*uefi.SecureBootEnroller).SetPlatformInfo` / `GetPlatformInfo` |

**Every `MISSING` in this table is deliberate for the write rows and a real gap
for the read rows.** Enrolling keys or writing an EFI variable over a network is
the remote-brick primitive this feature refuses to build. *Reading* firmware
state — Setup Mode, Secure Boot enforced, the db/dbx contents — is not dangerous
and has an obvious fleet use: a control plane cannot currently ask a node
"are you enforcing Secure Boot, and against which certificates?" over any
transport. It is recorded as a gap so it is a tracked debt rather than an
assumption.

Note also that the two `TRUSTED_PLATFORM` writers use **different vendor
GUIDs** ([engineering.md](engineering.md) §2.4), so a reader of one will not see
the other.

---

## 4. Key material

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Generate PK / KEK / DB keypairs and self-signed certificates | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `secureboot.NewXKMSManager(...).GenerateAll(ctx)` (and the per-role `GeneratePlatformKey` / `GenerateKeyExchangeKey` / `GenerateDatabaseKey`) |
| Report whether Secure Boot keys already exist | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*secureboot.XKMSManager).KeysExist()` |
| Resolve the on-disk key/certificate paths | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*secureboot.XKMSManager).GetKeyPaths()` |
| Obtain a `crypto.Signer` for PK / KEK / DB | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(*secureboot.XKMSManager).GetSigner(ctx, keyType)` |
| Construct a KMS-resident DB signer (hash-signing) | see §2 | see §2 | see §2 | see §2 | ✅ `secureboot.NewRemoteSigner(ctx, attrs, client)` |
| Generate the stable kernel module-signing key | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `secureboot.GenerateModuleSigningKey(ctx, cfg)` |
| Load the module-signing key back | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `secureboot.LoadModuleSigningKey(path)` |

The generic key-management surface (`KeyManagementService.Sign`, key create,
list, rotate) **is** on the transports and is documented in
[`docs/kms/`](../kms/). What is missing here is a *Secure Boot–shaped* wrapper
over it — "generate this platform's PK/KEK/DB set" is not an RPC.

---

## 5. Boot payload construction and signing

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Build a UKI (native Go PE patcher) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uki.NewBuilder(logger).BuildFile(u, path)` / `.Build(u, w)` |
| Build a UKI (objcopy) | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uki.NewObjcopyBuilder(logger)` |
| Add a custom PE section | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(UKIBuilder).AddSection(name, data)` |
| Select target architecture | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(UKIBuilder).SetArchitecture(arch)` |
| Parse a UKI | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `uki.NewParser(logger).ParseFile(path)` / `.Parse(r)` |
| List UKI sections | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(UKIParser).ListSections(r)` |
| Extract one UKI section | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(UKIParser).ExtractSection(r, name)` |
| Authenticode-sign a PE/COFF file | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `authenticode.NewSigner(ctx, opts).SignFile(in, out)` / `.Sign(r, w)` |
| Verify an Authenticode signature | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(Authenticode).VerifyFile(path)` / `.Verify(r)` |
| Extract the embedded signing certificate | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `(Authenticode).ExtractCertificateFile(path)` / `.ExtractCertificate(r)` |
| Read the signing time from a signed PE | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `authenticode.SigningTime(r)` |
| RFC 3161 timestamping | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | **PLANNED** — `SignerOptions.TimestampURL` is accepted and `addTimestamp` returns `ErrRFC3161NotImplemented`, logged as a non-fatal warning |

These are file-manipulation operations over local paths. There is no sensible
RPC shape for "build a UKI from `/boot/vmlinuz`" that does not amount to shipping
a kernel over the wire, so the absence is not a gap in the same sense as §3's
read rows. It is still recorded as `MISSING` so nobody has to re-derive that
conclusion.

---

## 6. Kernel module signing

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Sign a kernel module in place | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `modulesign.SignModule(koPath, signer, cert)` |
| Build the detached CMS + kernel trailer only | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `modulesign.BuildModuleSignature(content, signer, cert)` |
| Enumerate modules under `<rootfs>/lib/modules/<kver>` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | `MISSING — docs/13 G7` | ✅ `modulesign.EnumerateModules(rootfs, kver)` |

There is also **no CLI verb** for any of these ([cli.md](cli.md) §7). The only
production callers of `pkg/modulesign` today are the integration tests; in-tree
modules are signed by the kernel build itself via `CONFIG_MODULE_SIG_ALL`.
Out-of-tree module signing is a complete library with no operator-facing
surface — **PLANNED**.

---

## 7. Capabilities that do not exist anywhere

Recorded because the legacy documents in this folder describe them and an agent
must be able to tell "not exposed" from "not built".

| Capability | Status |
|---|---|
| Sign, flash, attest or OTA-update AVR firmware | **Not implemented.** `pkg/firmware`, `pkg/ota`, `pkg/avr` do not exist |
| Raspberry Pi OTP secure boot, boot-chain signing, A/B OTA | **Not implemented.** `pkg/rpi` does not exist |
| Android / GrapheneOS fastboot, AVB 2.0, hardware attestation | **Not implemented.** `pkg/android` does not exist |
| Firmware encryption (AES-128-CTR), ATECC608A support | **Not implemented** |
| A `firmware:` configuration section | **Not implemented** |

All PLANNED. See [architecture.md](architecture.md) §8–§9 and the legacy
[ROADMAP.md](ROADMAP.md).

---

## 8. Versioning and deprecation

REST under `/api/v1`; gRPC package `platform.v1`; QUIC `ProtocolVersion 0x01`.
Nothing in this feature is deprecated. The QUIC provisioning surface is
multiplexed under a single category opcode (`0xCF`) with a sub-opcode in the
first payload byte, because the single-byte opcode space is exhausted — adding a
provisioning operation means adding a sub-opcode, not a top-level opcode.

---

## 9. Related

- [`docs/daemon/api.md`](../daemon/api.md) — transports, frame constants, the
  canonical QUIC opcode table, and the status-byte vocabulary
- [`docs/provisioning/`](../provisioning/) — config delivery, EAB, nonces,
  device profiles, sessions
- [`docs/kms/`](../kms/) — the generic key-management transport surface
- [`docs/ima/api.md`](../ima/api.md) — the runtime-measurement half, which has
  no transport surface at all
- [architecture.md](architecture.md) · [engineering.md](engineering.md) ·
  [cli.md](cli.md) · [user.md](user.md)
