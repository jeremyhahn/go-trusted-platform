# Trust — Engineering

> **Status: NORMATIVE** · Scope: `pkg/trust` implementation contract · Last verified: 2026-10-11
> Conflicts with this document are defects. Fix them here first.
> The feature folder is: [architecture.md](architecture.md) · [engineering.md](engineering.md) · [cli.md](cli.md) · [api.md](api.md) · [user.md](user.md).

---

## 1. Exported surface

### Anchor (`pkg/trust/anchor.go`)

| Symbol | Contract |
|---|---|
| `AnchorSource` | interface: `AnchorCertificates(ctx) ([]*x509.Certificate, error)` |
| `AnchorSourceFunc` | function adapter for `AnchorSource` |
| `NewAnchor(source)` | returns `ErrNilAnchorSource` for a nil source |
| `(*Anchor).Certificates(ctx)` | CA certificates only (`IsCA`); `*ErrAnchorUnavailable` when the source errors; `ErrAnchorEmpty` when no CA remains |
| `(*Anchor).CAPool(ctx)` | pool of `Certificates` |
| `(*Anchor).TLSConfig(ctx)` | client config, `RootCAs` set, `MinVersion` TLS 1.2, `ServerName` left to the transport |
| `FileAnchorSource`, `NewFileAnchorSource(path)`, `Path()` | PEM file read on every call; `ErrAnchorFileUnset` for an empty path, `*ErrCAFileRead` for an unreadable file, `ErrCABundleParse` for a corrupt `CERTIFICATE` block; non-`CERTIFICATE` blocks are skipped |
| `(*App).PlatformAnchor()` (`pkg/app/platform_anchor.go`) | source = root of the IDevID issuing chain (`TPM.IDevIDCertificate` → `CA.RootCertificate`); `ErrPlatformAnchorNoIdentity` when TPM or CA is absent |

### Resolver (`pkg/trust/resolver.go`)

| Symbol | Contract |
|---|---|
| `Resolver` | `TLSConfig(ctx, class, endpoint)`, `CAPool(ctx, class, endpoint)`, `CABundlePEM(ctx, class)` |
| `NewResolver(config, logger, opts...)` | validates the config; `ErrNilConfig`, `ErrNilLogger`, validation errors, or `ErrTOFUPinStoreRequired` |
| `WithPinStore(PinStore)` | per-endpoint SPKI pins; take precedence over the scope's static pin |
| `WithTOFUPinStore(TOFUPinStore)` | required when any scope lists `tofu` |
| `WithTOFUConfirmFunc(fn)` | called before a new TOFU pin is persisted; an error aborts and stores nothing |
| `PinStore`, `TOFUPinStore`, `TOFUPin`, `Attempt`, `Strategy` | aliases of the go-xkms resolver types |
| `InstallToSystemTrust(bundlePEM, certPath)` (`install.go`) | writes the bundle, creating parent directories; does not refresh the OS store |

Endpoint is `host:port`; empty selects the scope's `server-url`. For the
`embedded` strategy `CABundlePEM` returns `(nil, nil)`. Successful pools are
cached per `(class, endpoint)` by the generic resolver.

### Config (`pkg/trust/config.go`)

| Symbol | Contract |
|---|---|
| `Class`, `ClassBootstrap` (`"bootstrap"`), `ClassBMC` (`"bmc"`), `Classes()` | stable class list; callers walk `Classes()` rather than keep their own |
| `Config{Bootstrap, BMC *ScopeConfig}` | the `trust:` section; an unset class fails resolution with `*ErrClassNotConfigured` |
| `DefaultConfig()` | `bootstrap` class with `[dane, noise, spki]`, 5 s per method. `tofu` is excluded on purpose |
| `Config.Scope(class)`, `Validate()`, `ToGeneric()` | `Validate` also resolves `spki.pin-file` into `spki.pin` |
| `StrategyAllowedForClass`, `AllowedStrategiesForClass` | the **single** query point for the allowlist; never hard-code the list in an error message |
| `StrategyDANE`, `StrategyNoise`, `StrategySPKI`, `StrategyEmbedded`, `StrategyCAFile`, `StrategyTOFU` | strategy names `dane`, `noise`, `spki`, `embedded`, `ca-file`, `tofu` |

## 2. Invariants

- The anchor is never cached and never configured; the platform CA has exactly
  one source per node type.
- A class not in `Classes()` does not exist. The allowlist map and `Classes()`
  are the only places a class is defined.
- Validation is **structural**: a strategy whose inputs are entirely absent is
  accepted (the resolver records a per-strategy failure and falls through); a
  *partial* strategy config is a hard error.
- `tofu` is never an implicit fallback and needs `WithTOFUPinStore`.
- Concurrency: `Anchor` and the resolver hold no mutable platform-side state;
  caching is inside the generic resolver.

## 3. Error semantics

All errors are typed (`pkg/trust/errors.go`); none are `fmt.Errorf`.

| Type | Returned when |
|---|---|
| `ErrNilConfig`, `ErrNilLogger` | `NewResolver` argument is nil |
| `*ErrInvalidConfig{Class, Field, Reason}` | no strategies; `noise` without `server-static-key` or `server-addr`; unreadable `spki.pin-file`; negative `per-method-timeout` |
| `*ErrStrategyNotAllowed{Class, Strategy}` | strategy outside the class allowlist |
| `*ErrClassNotConfigured{Class}` (alias `ErrScopeNotConfigured`) | class has no `ScopeConfig` |
| `*ErrNoStrategySucceeded{Class, Endpoint, Attempts}` | every strategy failed; `Unwrap() []error` exposes each attempt |
| `ErrTOFUPinStoreRequired` | `tofu` listed, no pin store |
| `ErrFetchFailed`, `ErrCABundleEmpty`, `ErrCABundleParse`, `ErrWriteFailed`, `ErrPinNotFound`, `ErrCAFileRead`, `ErrEndpointInvalid` | aliases of go-xkms errors; `errors.As` works unchanged |
| `ErrNilAnchorSource`, `*ErrAnchorUnavailable{Cause}`, `ErrAnchorEmpty`, `ErrAnchorFileUnset` | anchor construction and reads (see §1) |

Fail-closed: every path returns an error rather than a permissive TLS config.
At transport boundaries the proxy adapter maps unknown classes to
`ErrUnknownTrustClass` and a missing source to `ErrTrustSourceMissing`
(`pkg/sdn/gateway/proxysvc`), and wraps resolver failures in
`proxy.TrustResolveError`.

## 4. Configuration

The `trust:` section is read into `AppConfig.TrustConfig`. The config decoder
**ignores unknown keys**, so a retired `trust.default` or `trust.internal` loses
its settings silently; `pkg/trust/shipped_templates_test.go` checks every
shipped template for both.

```yaml
trust:
  bootstrap:                                   # or bmc
    strategies: [dane, noise, spki]            # required, ordered
    server-url: https://cp.example.com:8443    # the bundle SERVER, not the endpoint verified
    hostname: cp.example.com                   # DANE TLSA name; needed when server-url is an IP
    bundle-path: /api/v1/ca/bootstrap          # empty selects the library default
    per-method-timeout: 15s
    install-to-system-trust: true
    ca-file: /etc/trusted-platform/bmc-ca.pem  # ca-file strategy
    dane:  { dns-server: "10.0.0.2:8053" }
    noise: { server-addr: "cp.example.com:9446", server-static-key: "<64-hex>" }
    spki:  { pin: "<64-hex-sha256>" }          # or pin-file: /etc/trusted-platform/bootstrap-spki-pin
platform-ca-file: /etc/gatewayd/cp-ca.pem      # gatewayd only: the anchor's source
```

| Key | Notes |
|---|---|
| `strategies` | required per configured scope |
| `server-url` | used by bundle-fetch strategies (`noise`, `tofu`, and the `dane`/`spki` bundle path). Not consulted when `dane`/`spki` verify a caller-supplied endpoint on the TLS path |
| `dane.dns-server` | highest priority DANE resolver; else `dns.resolver.servers[0]`; else server IP on port 8053. See [`docs/bootstrap/engineering.md`](../bootstrap/engineering.md#5-configuration) for the `dns.*` and server-side keys |
| `spki.pin` / `spki.pin-file` | pin wins; the file is read at validation. A scope with neither is valid when a `PinStore` supplies per-endpoint pins |
| `platform-ca-file` | top-level key, **not** under `trust:`; required for gatewayd's gRPC platformd dial, secret store and `trust-class: platform` |

Kernel command-line parameters that populate this section at install time are
mapped in [`docs/reference/kernel-cmdline.md`](../reference/kernel-cmdline.md) §3a.
The BMC strategy tables per device template are in
[`docs/device-templates.md`](../device-templates.md).

## 5. Persistence

None in this package. TOFU pins persist through `quicbaas.NewTOFUPinStore` over
the SDK client. When a scope lists `tofu` and no storage backend is available,
`NewResolver` returns `ErrTOFUPinStoreRequired`, `App.TrustResolver()` logs a
warning and returns nil, and callers must gate trust-dependent work on that nil.

## 6. Test strategy

Unit only, in memory, fast: `anchor_test.go`, `config_test.go`,
`errors_test.go`, `install_test.go`, `resolver_test.go`,
`resolver_dane_test.go`, `shipped_templates_test.go`. Run
`make test-pkg PKG=./pkg/trust/`. Anchor consumers are covered by the
attestation, gateway and proxy suites. There is no transport surface, so there
is no multi-protocol integration target for this feature.

## 7. Observability

The generic resolver logs through the platform logger's `*slog.Logger`. The TOFU
confirm hook logs a warning with `host`, `port`, `spki_sha256`,
`cert_fingerprint` and `source` on each new pin. `ErrNoStrategySucceeded`
carries every attempt, in chain order, in its message.
