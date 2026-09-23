// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/tenant"
)

// DefaultRequestTimeout bounds one device conversation. A command that pages
// costs several round trips over a serial link, so this is generous by the
// standards of a local bus and still short enough that a wedged device does
// not hold a caller indefinitely.
const DefaultRequestTimeout = 2 * time.Second

// Config is everything a [Backend] needs that is not the device itself.
//
// The tenant is required and has no default. A record whose tenant were
// inferred would be a record nobody could later prove belonged to anyone, and
// retrofitting tenancy onto stored evidence costs far more than carrying it
// from the first commit.
type Config struct {
	// TenantID is the tenant that owns the device. Required, and validated
	// against the tenant package's own rules so this package and the key
	// space agree on what a legal identifier is.
	TenantID string

	// DeviceRef is the operator's label for the link this device is
	// reached on ("usb0", "bench-3"). Optional; recorded in evidence
	// metadata for audit trails and never used for routing.
	DeviceRef string

	// Platform is a human-readable board or product identifier, used to
	// enrich errors. Optional.
	Platform string

	// RequestTimeout bounds one device conversation. Zero selects
	// [DefaultRequestTimeout]; negative is refused.
	RequestTimeout time.Duration

	// Logger receives construction and relay events. Zero uses a logger
	// that discards, so a caller who does not want logs does not get a nil
	// dereference.
	Logger *slog.Logger

	// Clock stamps the relay time on evidence this gateway forwards. Zero
	// selects time.Now.
	//
	// It is injectable ONLY so the age rule can be tested deterministically.
	// It must never be wired to anything a device supplies: the device has
	// no clock, and the moment a device-supplied value reaches this field
	// the freshness guarantee is gone.
	Clock func() time.Time
}

// Validate checks the configuration and returns a typed error naming the
// first field that cannot be used.
func (c *Config) Validate() error {
	if c == nil {
		return ErrNilConfig{}
	}
	if _, err := tenant.TenantPath(c.TenantID); err != nil {
		return ErrInvalidTenant{TenantID: c.TenantID, Cause: err}
	}
	if c.RequestTimeout < 0 {
		return ErrInvalidConfig{Field: "RequestTimeout", Reason: "must not be negative"}
	}
	return nil
}

// requestTimeout resolves the configured timeout.
func (c *Config) requestTimeout() time.Duration {
	if c.RequestTimeout == 0 {
		return DefaultRequestTimeout
	}
	return c.RequestTimeout
}

// clock resolves the configured clock.
func (c *Config) clock() func() time.Time {
	if c.Clock == nil {
		return time.Now
	}
	return c.Clock
}

// logger resolves the configured logger.
func (c *Config) logger() *slog.Logger {
	if c.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return c.Logger
}
