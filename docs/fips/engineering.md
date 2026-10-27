# FIPS Mode — Engineering

> **Status: NORMATIVE** · Scope: the `fips` build tag, `GODEBUG=fips140=only`, `pkg/fips/` · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Selecting a FIPS build

| Step | Where |
|---|---|
| `WITH_FIPS ?= 0`: the switch, off by default | `Makefile:94` |
| `WITH_FIPS=1` **appends** `fips` to `BUILD_TAGS` | `Makefile:293-295` |
| `make -s print-build-tags` prints the assembled tag list for callers that run `go` directly | `Makefile:663-680` |
| `make test-fips` builds `./...` and then runs `make test`, both with `GOFIPS140=latest GODEBUG=fips140=only` and `WITH_FIPS=1` | `Makefile:1365-1382` |

Never pass `BUILD_TAGS="... fips"` on the command line. A command-line variable
replaces the Makefile's `+=` chain, so the build loses every codec. Under the old
nightly FIPS job that showed up as `no codec available for encoding` and was
reported as a FIPS finding (`Makefile:286-292`). The `go build` step of
`test-fips` therefore gets its tags from
`print-build-tags WITH_FIPS=1` (`Makefile:1381`).

`GOFIPS140=latest` links Go's FIPS 140-3 module into the binary.
`GODEBUG=fips140=only` makes that module refuse non-approved algorithms at run
time. `test-fips` uses `only`, not `on`, which still permits them
(`Makefile:1375-1377`).

## 2. Implementations the `fips` tag selects

Each row is a `//go:build fips` file with a `//go:build !fips` sibling. The FIPS
side is the only one linked into a tagged build.

| Package | FIPS file | What the FIPS build does | Default sibling |
|---|---|---|---|
| `pkg/attestation/workload` | `hash_sha1_fips.go:21` | `newSHA1` returns nil, so no SHA-1 PCR bank is computed. The bank can still be described | `hash_sha1.go` |
| `pkg/bmc` | `rmcp_algorithms_fips.go:33-72` | RMCP+ offers only HMAC-SHA256 / HMAC-SHA256-128. A controller that negotiates anything else gets `ErrFIPSAlgorithmNotApproved` (`rmcp_errors.go:171`). MD5 and SHA-1 are not imported | `rmcp_algorithms.go` |
| `pkg/cli/commands/vpn` | `client_planes_fips.go:22-24` | The client has no kernel data plane (no WireGuard); MASQUE remains | `client_planes.go` |
| `pkg/ima` | `hash_sha1_fips.go:22`, `:41` | `newSHA1` returns `ErrFIPSHashNotApproved` (`fips_errors.go:15`). An event labelled sha1/md5, or carrying a 20-byte template hash, is never reported as verified | `hash_sha1.go` |
| `pkg/iso` | `apk_checksum_fips.go:26-48` | The `APKINDEX` `Q1` checksum is SHA-1, so offline APK prefetch fails closed with `ErrFIPSAPKChecksumUnavailable` and the whole index is abandoned | `apk_checksum.go` |
| `pkg/sdn/bgp` | `auth_fips.go:23` | TCP-MD5 session auth is refused at validation with `ErrAuthTypeUnavailableInFIPS` (`types.go:1105-1106`, `errors.go:913`) | `auth_nofips.go` |
| `pkg/sdn/gateway/services/vpn` | `dataplane_fips.go:18-20` | MASQUE only. A `wireguard` data plane is not a known kind, so `Config.Validate` returns `ErrInvalidConfig` | `dataplane_wireguard.go` |
| `pkg/sdn/ipsec` | `proposals_fips.go:22-25` | IKE `aes256gcm16-prfsha384-ecp384`, ESP `aes256gcm16-ecp384-esn`, without the default build's hybrid `ke1_mlkem768` | `proposals_nofips.go` |
| `pkg/sdn/tunnel` | `wireguard_fips.go:23-38` | The `wireguard` transport is refused with `ErrTransportUnavailable` (`errors.go:102`) by `ValidateTransport` (`types.go:249-250`) and by create/rekey | `wireguard.go`, `wireguard_client.go`, `wireguard_hub.go` |
| `pkg/secureboot` | `ski_fips.go:27` | The Subject Key Identifier is SHA-256 truncated to 20 bytes (RFC 5280 §4.2.1.2). The default build uses SHA-1 and is byte-identical to before | `ski.go` |
| `pkg/vpn/agent` | — | `dataplane_wireguard.go` is `!fips` only; the FIPS agent has no WireGuard plane | `dataplane_wireguard.go` |

## 3. Runtime checks keyed on `fips140.Enabled()`

These files are **untagged**. A binary built without the tag can still be run
under `fips140=only`, and Go's module then panics on the unapproved call. Each
check below refuses earlier, with a typed error.

| Check | Where | Refusal |
|---|---|---|
| IPMI password or KG key under 14 bytes (112 bits) | `pkg/bmc/rmcp_fips_keys.go:23`, `:43` | `ErrFIPSKeyTooShort` (`pkg/bmc/rmcp_errors.go:192`) at session open; Redfish is unaffected ([bmc engineering](../bmc/engineering.md)) |
| DNSSEC `nsec-mode: nsec3` | `pkg/dns/config.go:322`, `:333` | `ErrFIPSNSEC3Unsupported` (`pkg/dns/dnssec_errors.go:105`) before the server starts; NSEC is accepted ([dns engineering](../dns/engineering.md)) |
| AES-GCM with a caller-supplied nonce | `pkg/crypto/aesgcm/aesgcm.go:67-73`, `pkg/registry/encryption.go:395`, `pkg/registry/encryption_envelope.go:39` | Not a refusal. These paths use random-nonce GCM so they run under `fips140=only` (#209) |

## 4. `pkg/fips`: the kernel-indicator policy

`pkg/fips` reads `/proc/sys/crypto/fips_enabled`, a fixed path that cannot be
overridden (`detect.go:63`). It never consults `GODEBUG`.

| Symbol | Where | Contract |
|---|---|---|
| `DetectActivation() (bool, error)` | `detect.go:92-108` | absent → `false`; `1` → `true`; `0` → `false`; other content → `ErrFIPSIndicatorMalformed`; read error → `ErrFIPSIndicatorUnreadable` |
| `IsEnabled() bool` | `detect.go:71-83` | Fails **closed**: any detection error reports active |
| `GetKDF()`, `GetHash()` | `detect.go:115-120`, `:148-150` | `pbkdf2` when active, else `argon2id`; hash is always `sha256` |
| `ValidateKDFForMode(kdf, active)` | `detect.go:202-230` | `pbkdf2`, `pbkdf2-sha256/384/512` always pass. When active, `pbkdf2-sha1`, `argon2id` and `argon2i` give `ErrKDFNotApproved`. An unknown name gives `ErrUnknownKDF` in either mode |
| `ValidateHashForMode(hash, active)` | `detect.go:243-256` | `sha1` gives `ErrHashNotApproved` when active |
| `ResolveKeyslotPolicy(kdf, hash *string)` | `detect.go:300-314` | When active, fills an empty KDF with `pbkdf2` and an empty hash with the PRF, then validates |
| `ResolveFormatKeyslotPolicy(kdf, hash *string)` | `detect.go:330-380` | The format variant. Translates hash-qualified KDF aliases; `ErrQualifiedKDFHashConflict`; `ErrHashUnsupportedByLUKS` (the LUKS AF splitter takes only sha256/sha512) |
| `ValidateLUKSFormatDigest(hash)` | `detect.go:433-438` | The sha256/sha512 limit, in every mode |
| `Installer`, `RegisterInstaller`, `NewInstaller` | `interface.go:22-70` | The OS-level FIPS installer registry. `ErrUnsupportedOS` when no installer is registered for the OS |

The error types are in `algorithm_errors.go` and `errors.go`.

Every LUKS2 keyslot write goes through this policy:

- `pkg/storage/luks/fips_policy.go:14`, `:22`
- `pkg/app/backends/luks_fips.go:29`, `:44`
- `pkg/installer/fido2_enroll.go:433`
- the initrd strategies, which call `GetKDF`/`GetHash`: `pkg/initrd/install.go:160`, `strategy_fido2.go:179`, `strategy_tpm_pcr.go:431`, `strategy_tpm_nopcr.go:233`

`pkg/arch/luks_keyslot_policy_test.go:35` fails `make test` if a keyslot call
skips the policy.

The installer's format path ORs the indicator with its own `--fips`:
`fipsActive := config.FIPS || fips.IsEnabled()`
(`pkg/installer/luks_algorithms.go:36`). Under that flag:

- an Argon2 KDF becomes PBKDF2 (`:40-60`);
- `pbkdf2-sha1` is refused (`:45-57`);
- a SHA-1 hash is refused (`:68-70`).

The policy governs keyslot **creation** only. Opening an existing Argon2
keyslot is not refused ([luks engineering](../luks/engineering.md), go-luks2
v0.2.0).

## 5. The FIPS OS image

| Piece | Where |
|---|---|
| `os.fips` (installer YAML) copies to `Disk.Encryption.FIPS` | `pkg/installer/types.go:407`, `:257`; `pkg/installer/installer.go:147-149` |
| The `fips` profile | `pkg/installer/profiles.go:43`, `:72` |
| Alpine FIPS installer, registered as `alpine` | `pkg/installer/alpine/fips.go:28-31` |
| Phase 1, before the UKI: install `vmlinuz-fips` and its modules from `/media/cdrom/fips-artifacts/` | `pkg/installer/installer.go:303-308`; `pkg/installer/alpine/fips.go:192-266` |
| The UKI uses `/boot/vmlinuz-fips`; `fips=1` is appended to the command line | `pkg/installer/installer.go:1145-1150`, `:1209-1211` |
| Phase 2, after signing: the OpenSSL FIPS provider, `openssl fipsinstall`, and an `openssl.cnf` with `default_properties = fips=yes` | `pkg/installer/installer.go:388-392`; `pkg/installer/alpine/fips.go:269-467` |
| `Verify`: `fips.so`, `fipsmodule.cnf` and `fips_sect` are present | `pkg/installer/alpine/fips.go:98-126` |
| ISO: x86_64 only (`FIPSUnsupportedArchitectureError`); builder containers `fips-kernel-builder` and `openssl-fips-provider-builder`; name suffix `-fips` | `pkg/iso/types.go:322-324`, `:427-435`, `:454-456` |
| ISO: artifacts copied, `--fips` added to the install command, `fips=1` set; no stock kernel or `gatewayd` packages are prefetched | `pkg/iso/customize.go:227-232`, `:4297-4298`, `:5779-5781`; `pkg/iso/prefetch.go:299`, `:375` |

The kernel and provider builders are `build/docker/fips-kernel-builder/` and
`build/docker/openssl-fips-provider/`.

## 6. Tests and CI

- **Test-only tagged files** pin both sides of each pair. Examples:
  - `pkg/api/noise/server_fips_test.go:29-44`: a FIPS build refuses the Curve25519 listener key with `ErrKeyGenerationFailed`;
  - `pkg/dns/dnssec_nsec3_test.go` (`!fips`);
  - `pkg/bmc/rmcp_known_vectors_test.go` and `rmcp_legacy_algorithms_test.go` (`!fips`);
  - `pkg/sdn/gateway/tunnels_fips_test.go`.
- **`CI / FIPS`** is the `fips` job in `.github/workflows/ci.yml:666-695`:
  - it runs `make test-fips` in the full tier: on push to `main`, the nightly schedule, `workflow_dispatch` and a pull request labelled `ci:full`, never on an ordinary pull request (`ci.yml:682`);
  - it is **not** in `ci-gate`'s `needs`, so it does not block a merge;
  - `pkg/arch/citiers_test.go` fails `make test` if the job is gated, a gated job needs it, or its `if:` is not the full tier's (`ci.yml:673-674`).
- **`Nightly / FIPS`** runs the same target (`.github/workflows/nightly.yml:162-186`) on `workflow_dispatch` only, and publishes a non-gating status (`:433`).
  - The header of that file lists what is still red and who owns it.
  - A panic under `fips140=only` aborts the whole test binary, so its failure count is a lower bound.

## 7. Planned

| Item | Issue |
|---|---|
| PBKDF2-HMAC-SHA256 password hashing under FIPS activation. `pkg/crypto/argon2` is Argon2id in every mode today | **Planned (#26)** |
| An approved P-256 suite for the Noise bootstrap listener; a FIPS build refuses the only suite it has | **Planned (#518)** |
| NSEC3 under FIPS: the refusal stands pending the owner's decision | #249 |
| Setting `GODEBUG=fips140=only` automatically from the kernel indicator | **Planned** — no issue filed |
| `CI / FIPS` as a merge gate | **Planned** — off the gate until its upstream failures clear (`ci.yml:670-672`) |
