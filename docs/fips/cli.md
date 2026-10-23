# FIPS Mode — CLI

> **Status: NORMATIVE** · Scope: `--fips` flags and the FIPS `make` targets · Last verified: 2026-10-14
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

FIPS mode has no command group of its own. It is a boolean `--fips` flag on the
commands that build or install a system, plus three `make` controls.

## 1. `make` controls

| Control | Effect | Where |
|---|---|---|
| `WITH_FIPS=1` | Adds the `fips` build tag to every `make` build and test target | `Makefile:94`, `:293-295` |
| `make -s print-build-tags [WITH_FIPS=1]` | Prints the assembled tag list; use it for any `go` command that `make` does not wrap | `Makefile:673-680` |
| `make test-fips` | Builds `./...`, then runs `make test`, both tagged `fips` under `GOFIPS140=latest GODEBUG=fips140=only` | `Makefile:1365-1382` |

```sh
make build WITH_FIPS=1
go vet -tags "$(make -s print-build-tags WITH_FIPS=1)" ./pkg/...
make test-fips
```

## 2. `--fips` flags

Each flag is a boolean, default `false`, never required.

| Command | Effect on `main` | Where |
|---|---|---|
| `platformctl iso create --fips` | Builds a FIPS ISO: x86_64 only, FIPS kernel and OpenSSL provider, `fips=1`, `-fips` name suffix, `--fips` passed to the installer. The stock kernel is not prefetched (`pkg/iso/prefetch.go:299`) | `pkg/cli/commands/iso/create.go:141`, `:474` |
| `platformctl install system --fips` | Sets `os.fips` (overriding the config file only when given). LUKS uses `pbkdf2`, and the FIPS kernel and OpenSSL provider are installed | `pkg/cli/commands/install/system.go:123`, `:334`, `:348`, `:506-508`, `:360-365` |
| `platform-initrd boot --fips`, `platform-initrd recovery --fips` | Recorded in the initrd configuration (`pkg/initrd/types.go:113`) but **not read**. The keyslot KDF follows the kernel's FIPS mode (`pkg/initrd/install.go:160`) | `pkg/boot/commands/boot.go:103`, `recovery.go:75` |
| `platformctl firstboot --fips` | Parsed but **not read** | `pkg/cli/commands/firstboot/firstboot.go:103` |

```sh
platformctl iso create --fips --output platform-fips.iso
platformctl install system --fips --disk /dev/sda
```

The `fips` installer profile (`pkg/installer/profiles.go:43`) sets the same
`os.fips` from a profile instead of a flag.
