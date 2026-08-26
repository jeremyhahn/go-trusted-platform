// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package controlplane

import (
	"net/url"
	"time"
)

// Config is the gatewayd `control-plane:` configuration section. It
// describes how the daemon reports telemetry to the platform control
// plane's REST gateway routes (POST /api/v1/gateway/telemetry) and where
// desired configuration is fetched from
// (GET /api/v1/gateway/desired-config/{id}).
type Config struct {
	// Enabled turns the periodic telemetry reporter on.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// BaseURL is the control plane's API base, e.g.
	// https://cp.example.com:8443. The reporter appends the gateway
	// control-plane route paths, so it must be scheme and host only —
	// a path, query or fragment is refused rather than ignored, because
	// appending to one silently re-targets the request (see
	// validateBaseURL). A bare trailing slash is normalized away.
	BaseURL string `yaml:"base-url" json:"base_url" mapstructure:"base-url"`

	// GatewayID identifies this gatewayd toward the control plane. When
	// empty the gateway node's configured ID is used.
	//
	// It is NOT a free-form label: the control plane binds the reported
	// gateway_id to the Subject Common Name of the client certificate
	// below and refuses (403) anything else, so a gateway reaches only
	// its own record. BuildReporter therefore refuses to assemble a
	// reporter whose resolved ID is not that CN — the mismatch is caught
	// at startup rather than as a permanent 403 on every telemetry tick.
	GatewayID string `yaml:"gateway-id,omitempty" json:"gateway_id,omitempty" mapstructure:"gateway-id"`

	// Interval is the duration between telemetry pushes. Zero selects the
	// reporter default (30s).
	Interval time.Duration `yaml:"interval,omitempty" json:"interval,omitempty" mapstructure:"interval"`

	// CertFile is the gateway's client certificate (IDevID-derived
	// platform identity) presented to the control plane at TLS handshake
	// time. Required when the section is enabled: the telemetry identity
	// claim is the mTLS client certificate, so reporting without one is
	// refused at configuration time rather than silently unauthenticated.
	CertFile string `yaml:"cert-file" json:"cert_file" mapstructure:"cert-file"`

	// KeyFile is the private key matching CertFile. Required when the
	// section is enabled.
	KeyFile string `yaml:"key-file" json:"key_file" mapstructure:"key-file"`

	// CAFile optionally anchors server verification to an explicit CA
	// bundle. When empty the trust resolver's internal-class CA pool is
	// used if a trust: section is configured, falling back to the
	// operating-system trust store otherwise.
	CAFile string `yaml:"ca-file,omitempty" json:"ca_file,omitempty" mapstructure:"ca-file"`
}

// MinInterval is the lowest telemetry interval Validate accepts. It
// exists to catch unitless YAML values (`interval: 30` decodes to 30
// nanoseconds) before they become a telemetry hot loop.
const MinInterval = time.Second

// Validate checks the control-plane section for internal consistency.
// A disabled section always validates. An enabled section fails closed
// without the mTLS client identity (cert-file + key-file) and without an
// https base-url — the client certificate is the telemetry identity
// claim, and it is only ever presented over TLS.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	if c.BaseURL == "" {
		return ErrMissingField{Field: "base-url"}
	}
	if err := validateBaseURL(c.BaseURL); err != nil {
		return err
	}
	if c.CertFile == "" {
		return ErrMissingField{Field: "cert-file"}
	}
	if c.KeyFile == "" {
		return ErrMissingField{Field: "key-file"}
	}
	if c.Interval < 0 {
		return &ErrConfigInvalid{Field: "interval", Reason: "cannot be negative"}
	}
	if c.Interval > 0 && c.Interval < MinInterval {
		return &ErrConfigInvalid{Field: "interval", Reason: "below the 1s minimum; did you mean a duration like 30s?"}
	}
	return nil
}

// validateBaseURL requires an absolute https URL with a host and no
// embedded credentials.
//
// The scheme check is a fail-closed authentication gate, not cosmetics:
// net/http performs no TLS handshake for a non-https URL, so the
// cert-file/key-file this section mandates would never be presented and
// telemetry would leave the gateway in cleartext, unauthenticated —
// while the configuration still read as mTLS-protected. Userinfo is
// refused because a bearer-style credential in the URL contradicts the
// same contract: the client certificate is the only identity claim.
func validateBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return &ErrConfigInvalid{Field: "base-url", Reason: "is not a valid URL"}
	}
	if u.Scheme != "https" {
		return &ErrConfigInvalid{
			Field:  "base-url",
			Reason: "must be an absolute https:// URL; the mTLS client certificate is the telemetry identity and is never presented without TLS",
		}
	}
	if u.Host == "" {
		return &ErrConfigInvalid{Field: "base-url", Reason: "must include a host"}
	}
	if u.User != nil {
		return &ErrConfigInvalid{Field: "base-url", Reason: "must not embed userinfo credentials"}
	}
	// Suffix components are refused rather than ignored. The reporter
	// appends the control-plane route paths to this value, so anything
	// past the host silently re-targets the request instead of failing:
	// a base of "https://cp.example.com?tenant=x" parses with an EMPTY
	// path and swallows "/api/v1/gateway/telemetry" into the query, so
	// every push goes to "/" — the reporter starts, reports success at
	// the config layer, and never reaches the control plane at all. A
	// path prefix is refused for the same reason and because none is
	// supported: the routes are absolute under /api/v1/gateway.
	if u.Path != "" && u.Path != "/" {
		return &ErrConfigInvalid{
			Field:  "base-url",
			Reason: "must not carry a path; the control-plane routes are absolute under /api/v1/gateway",
		}
	}
	if u.RawQuery != "" {
		return &ErrConfigInvalid{Field: "base-url", Reason: "must not carry a query string"}
	}
	if u.Fragment != "" {
		return &ErrConfigInvalid{Field: "base-url", Reason: "must not carry a fragment"}
	}
	return nil
}
