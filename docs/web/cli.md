# Web Console and Web Server — CLI

> **Status: NORMATIVE** · Scope: web-related CLI surface · Last verified: 2026-08-18
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. There is no `platformctl web` command group

**This feature has no command group of its own, and that is deliberate.** The
web server is configured through the `webservices:` section of the platform
configuration file and started by `platformd` when that section exists; the
console is a static bundle produced by a build, not by a CLI verb. There is
nothing to add, get, list or delete at runtime.

Grepped 2026-08-18: `pkg/cli/commands/` contains no `web`, `webserver` or
`webservice` package, and `pkg/cli/commands/root.go` registers no such
subcommand.

Three real touchpoints exist, and they are all below.

---

## 2. `platformctl iso create --webui`

The one CLI flag that is about this feature. It selects the console bundle
baked into an installer ISO.

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--webui` | string | `""` | Path to a WebUI directory or tarball — `public_html` or `public_html.tar.gz` |

**Resolution order** (`pkg/cli/commands/iso/iso_builder.go: resolveWebUIPath`):

1. The explicit `--webui` path. If it does not exist, the build fails with
   `specified WebUI path not found: <path>`.
2. `public_html.tar.gz` in the current working directory.
3. `public_html/` in the current working directory.
4. **Auto-build** — the builder runs `make build-public-html` itself and then
   re-checks for the tarball and the directory. A failure here reports
   `failed to auto-build WebUI` and tells you to run the target by hand to
   diagnose it.
5. If nothing is found after all that, the build **continues without a WebUI**
   and logs `WebUI auto-build completed but no output found - continuing
   without WebUI`. An ISO with no console is a successful build, not an error —
   check the log if a freshly installed node serves nothing at `/`.

```bash
# Explicit bundle
platformctl iso create --config iso.yaml --webui ./public_html.tar.gz

# Auto-detect from the working directory, or auto-build
platformctl iso create --config iso.yaml
```

The installer lays the bundle down at `<install-dir>/public_html`, mode 755 for
directories and 644 for files, owned by root. Point `webservices[].home` at
that path.

Global `platformctl` flags (`--config`, `--context`, `--transport`,
`--server`, `--server-name`, `--output`, `--verbose`, `--no-color`) apply as
everywhere else; `iso create` is a **local** command and does not contact a
daemon.

---

## 3. `platformd` — how the server starts

`platformd serve` starts the web services automatically when a `webservices:`
(or singular `webservice:`) section is present in the configuration. **There is
no `--web`, `--http-port`, `--tls-port` or `--home` flag** — the listener
addresses, the static root, TLS identity, CORS, virtual hosts and JWT settings
are all configuration
([engineering.md](engineering.md) §6, [`docs/cli/platformd.md`](../cli/platformd.md)).

Consequences worth stating:

- **To change a port, edit the config and restart.** There is no override.
- **A binary built with `WITH_WEB=1` ignores `home` entirely** and serves the
  embedded bundle. There is no runtime flag to prefer the disk copy; that is a
  build-time decision.

---

## 4. Build and test targets

Not CLI verbs, but the commands people actually run for this feature. Full
detail in [engineering.md](engineering.md) §8–9.

From the repository root:

```bash
make build WITH_WEB=1     # embed the console in the binary (platform_web tag)
make web-build            # build to public_html/ + public_html.tar.gz
make build-public-html    # devcontainer build, adds Swagger UI under /swagger
make web-lint             # eslint + tsc --noEmit
make web-test             # Playwright E2E against a mocked backend
make web-test-ui          # the same, interactive
make web-test-webauthn FRONTEND_URL=https://console.example.com:8443
make web-clean            # remove .next, out, node_modules, embed dist
```

From `web/`:

```bash
make dev                  # backend in a container + frontend on the host, port 3000
make status               # container / backend / frontend state
make backend-logs         # tail the containerised platformd log
make test-e2e             # mocked-backend Playwright suite
make test-integration     # real-backend suite (test/integration/web)
make stop-all             # stop the backend and the container
```

**`make dev-standalone` is advertised by `web/Makefile`'s `help` target and
declared `.PHONY`, but no rule defines it.** Running it fails. Recorded as a
defect, not documented as a feature.

**The package manager is `npm`.** Every Makefile path uses it; the
pre-migration documents' `yarn` invocations are stale.

---

## 5. Parity

`conventions/feature-docs.md` §4 requires every verb here to have a matching
definition in the integration parity suite. **This feature contributes no verbs
to a command group**, so there is nothing to pair — the single flag it owns
(`iso create --webui`) belongs to the ISO command group and is covered by
`pkg/cli/commands/iso/create_test.go`, which asserts `webui` is among the
registered flags.

Note also that this repository defines **no `CommandDefinition` type** (grepped
repo-wide, 2026-08-18), so the convention's literal wording has no referent
here.

---

## 6. Related

- [architecture.md](architecture.md) · [engineering.md](engineering.md) · [api.md](api.md) · [user.md](user.md)
- [`docs/cli/platformd.md`](../cli/platformd.md) — the daemon that hosts this server
- [`docs/cli/platformctl.md`](../cli/platformctl.md) · [`docs/cli/global-flags.md`](../cli/global-flags.md)
