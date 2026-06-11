// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package trust

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	xkmsresolver "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/resolver"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Resolver resolves trust material for a (class, endpoint) pair by walking
// the class's ordered strategy chain and returning the first success.
type Resolver interface {
	// TLSConfig returns a *tls.Config whose certificate verification is
	// anchored by the first strategy in the class chain that can produce
	// one. The endpoint is the intended peer in "host:port" form; when
	// empty, the scope's server-url is used.
	TLSConfig(ctx context.Context, class Class, endpoint string) (*tls.Config, error)

	// CAPool returns an *x509.CertPool holding the CA bundle the first
	// successful strategy established. Successful pools are cached per
	// (class, endpoint).
	CAPool(ctx context.Context, class Class, endpoint string) (*x509.CertPool, error)

	// CABundlePEM returns the raw PEM CA bundle for the class. For the
	// embedded strategy it returns (nil, nil): the OS trust store is
	// authoritative and there is nothing to install.
	CABundlePEM(ctx context.Context, class Class) ([]byte, error)
}

// PinStore supplies per-endpoint SPKI pins (e.g. captured during BMC
// enrollment). A store with no pin for the endpoint returns
// *ErrPinNotFound so the resolver can fall back to the scope's static pin.
type PinStore = xkmsresolver.PinStore

// CABundleProvider supplies the platform CA bundle PEM for the platform-ca
// strategy.
type CABundleProvider = xkmsresolver.CABundleProvider

// TOFUPinStore is the TOFU pin persistence store required by the tofu
// strategy. Use bootstrap.NewStoragePinStore to construct a storage-backed
// instance.
type TOFUPinStore = xkmsresolver.TOFUPinStore

// TOFUPin is the TOFU pin record type. Fields include Host, Port, SPKISHA256,
// CertFingerprint, FirstSeen, and Source.
type TOFUPin = xkmsresolver.TOFUPin

// Option configures optional resolver collaborators.
type Option func(*resolverOptions)

// resolverOptions holds the resolver options before the generic resolver
// is constructed.
type resolverOptions struct {
	pinStore      PinStore
	platformCA    CABundleProvider
	tofuPinStore  TOFUPinStore
	tofuConfirmFn func(ctx context.Context, pin *xkmsresolver.TOFUPin) error
}

// WithPinStore injects a per-endpoint SPKI pin source. Endpoint pins take
// precedence over the scope's static pin.
func WithPinStore(store PinStore) Option {
	return func(o *resolverOptions) {
		o.pinStore = store
	}
}

// WithPlatformCA injects the platform CA bundle source required by the
// platform-ca strategy.
func WithPlatformCA(provider CABundleProvider) Option {
	return func(o *resolverOptions) {
		o.platformCA = provider
	}
}

// WithTOFUPinStore injects the TOFU pin persistence store required by the
// tofu strategy. Required whenever any class chain lists StrategyTOFU.
func WithTOFUPinStore(store TOFUPinStore) Option {
	return func(o *resolverOptions) {
		o.tofuPinStore = store
	}
}

// WithTOFUConfirmFunc injects an optional confirmation hook called before a
// newly captured TOFU pin is persisted. Returning an error aborts the
// bootstrap and prevents pin storage.
func WithTOFUConfirmFunc(fn func(ctx context.Context, pin *xkmsresolver.TOFUPin) error) Option {
	return func(o *resolverOptions) {
		o.tofuConfirmFn = fn
	}
}

// resolver is the production Resolver implementation. It wraps the generic
// xkms resolver with platform-level class-to-scope mapping.
type resolver struct {
	generic xkmsresolver.Resolver
}

// Compile-time interface check.
var _ Resolver = (*resolver)(nil)

// NewResolver validates the configuration and constructs a Resolver.
//
// The logger's underlying *slog.Logger is passed to the generic resolver;
// the platform logger wraps slog so this is always a no-op adapter.
//
// When the tofu strategy is listed in any class and no WithTOFUPinStore
// option is provided, NewResolver returns ErrTOFUPinStoreRequired.
func NewResolver(config *Config, logger *logging.Logger, opts ...Option) (Resolver, error) {
	if config == nil {
		return nil, ErrNilConfig{}
	}
	if logger == nil {
		return nil, ErrNilLogger{}
	}

	// Platform-level validation: class allowlists + pin-file resolution.
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Collect platform options.
	var o resolverOptions
	for _, opt := range opts {
		opt(&o)
	}

	// Build generic resolver options from the platform options.
	genericOpts := []xkmsresolver.Option{
		xkmsresolver.WithLogger(logger.Slog()),
	}
	if o.pinStore != nil {
		genericOpts = append(genericOpts, xkmsresolver.WithPinStore(o.pinStore))
	}
	if o.platformCA != nil {
		genericOpts = append(genericOpts, xkmsresolver.WithCABundleProvider(o.platformCA))
	}
	if o.tofuPinStore != nil {
		genericOpts = append(genericOpts, xkmsresolver.WithTOFUPinStore(o.tofuPinStore))
	}
	if o.tofuConfirmFn != nil {
		genericOpts = append(genericOpts, xkmsresolver.WithTOFUConfirmFunc(o.tofuConfirmFn))
	}

	// Project platform Config into the generic resolver config (includes
	// platform-ca → provider-ca normalisation).
	genericCfg := config.ToGeneric()

	gen, err := xkmsresolver.New(genericCfg, genericOpts...)
	if err != nil {
		return nil, err
	}
	return &resolver{generic: gen}, nil
}

// TLSConfig delegates to the generic resolver, mapping the platform Class
// to its scope string.
func (r *resolver) TLSConfig(ctx context.Context, class Class, endpoint string) (*tls.Config, error) {
	tlsCfg, err := r.generic.TLSConfig(ctx, string(class), endpoint)
	if err != nil {
		return nil, r.wrapScopeErr(err, class, endpoint)
	}
	return tlsCfg, nil
}

// CAPool delegates to the generic resolver, mapping the platform Class to
// its scope string.
func (r *resolver) CAPool(ctx context.Context, class Class, endpoint string) (*x509.CertPool, error) {
	pool, err := r.generic.CAPool(ctx, string(class), endpoint)
	if err != nil {
		return nil, r.wrapScopeErr(err, class, endpoint)
	}
	return pool, nil
}

// CABundlePEM delegates to the generic resolver, mapping the platform Class
// to its scope string.
func (r *resolver) CABundlePEM(ctx context.Context, class Class) ([]byte, error) {
	pem, err := r.generic.CABundlePEM(ctx, string(class))
	if err != nil {
		return nil, r.wrapScopeErr(err, class, "")
	}
	return pem, nil
}

// wrapScopeErr converts generic resolver errors into platform-typed errors.
//
// ErrScopeNotConfigured (generic, Scope string) → ErrClassNotConfigured
// (platform, Class Class) so existing call sites that errors.As against
// ErrClassNotConfigured keep working.
//
// ErrNoStrategySucceeded (generic, Scope string) → ErrNoStrategySucceeded
// (platform, Class Class) for the same reason.
//
// All other errors pass through unchanged.
func (r *resolver) wrapScopeErr(err error, class Class, endpoint string) error {
	if _, ok := err.(*xkmsresolver.ErrScopeNotConfigured); ok {
		return &ErrClassNotConfigured{Class: class}
	}
	if asNS, ok := err.(*xkmsresolver.ErrNoStrategySucceeded); ok {
		return &ErrNoStrategySucceeded{
			Class:    class,
			Endpoint: endpoint,
			Attempts: asNS.Attempts,
		}
	}
	return err
}
