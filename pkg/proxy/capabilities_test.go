package proxy

import (
	"crypto/tls"
	"errors"
	"testing"
)

// capsChain is a fakeAuth that reports configurable capabilities.
type capsChain struct {
	fakeAuth
	caps ChainCapabilities
}

func (c *capsChain) Capabilities() ChainCapabilities { return c.caps }

// mtlsOnlyCaps mirrors the production Chain without zone collaborators.
var mtlsOnlyCaps = ChainCapabilities{MTLS: true}

// zoneCaps mirrors the production Chain with zone collaborators.
var zoneCaps = ChainCapabilities{MTLS: true, Zones: true}

func TestChainCapabilitiesResolution(t *testing.T) {
	t.Run("reporter is consulted", func(t *testing.T) {
		got := chainCapabilities(&capsChain{caps: mtlsOnlyCaps})
		if got != mtlsOnlyCaps {
			t.Errorf("caps = %+v, want %+v", got, mtlsOnlyCaps)
		}
	})
	t.Run("non-reporter assumed fully capable", func(t *testing.T) {
		got := chainCapabilities(&fakeAuth{})
		want := ChainCapabilities{MTLS: true, Token: true, Attestation: true, OPA: true, Zones: true}
		if got != want {
			t.Errorf("caps = %+v, want %+v", got, want)
		}
	})
}

// TestCheckFailClosedCapabilities pins the construction-time rejection of
// routes demanding capabilities the injected chain does not report.
func TestCheckFailClosedCapabilities(t *testing.T) {
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	base := func(mutate func(*Config)) *Config {
		cfg := authConfig("http://10.0.0.1:8080")
		mutate(&cfg)
		return &cfg
	}
	tests := []struct {
		name    string
		cfg     *Config
		deps    Deps
		wantErr error
	}{
		{
			"token mode without token capability",
			base(func(c *Config) { c.Routes[0].Auth.Mode = AuthModeToken }),
			Deps{Auth: &capsChain{caps: mtlsOnlyCaps}, ServerTLS: serverTLS},
			ErrTokenAuthNotConfigured,
		},
		{
			"mtls-or-token without token capability",
			base(func(c *Config) { c.Routes[0].Auth.Mode = AuthModeMTLSOrToken }),
			Deps{Auth: &capsChain{caps: mtlsOnlyCaps}, ServerTLS: serverTLS},
			ErrTokenAuthNotConfigured,
		},
		{
			"mtls without mtls capability",
			base(func(*Config) {}),
			Deps{Auth: &capsChain{caps: ChainCapabilities{Token: true}}, ServerTLS: serverTLS},
			ErrMTLSAuthNotConfigured,
		},
		{
			"attestation without gate",
			base(func(c *Config) { c.Routes[0].Auth.RequireAttestation = true }),
			Deps{Auth: &capsChain{caps: zoneCaps}, ServerTLS: serverTLS},
			ErrAttestationGateNotConfigured,
		},
		{
			"opa policy without opa capability",
			base(func(c *Config) { c.Routes[0].Auth.OPAPolicy = "proxy_authz" }),
			Deps{Auth: &capsChain{caps: zoneCaps}, ServerTLS: serverTLS},
			ErrOPANotConfigured,
		},
		{
			"allowed zones without zone capability",
			base(func(c *Config) { c.Routes[0].Auth.AllowedZones = []string{"control-plane"} }),
			Deps{Auth: &capsChain{caps: mtlsOnlyCaps}, ServerTLS: serverTLS},
			ErrZoneEnforcementNotConfigured,
		},
		{
			"default backend zone without zone capability",
			base(func(c *Config) { c.Defaults.BackendZone = "internal" }),
			Deps{Auth: &capsChain{caps: mtlsOnlyCaps}, ServerTLS: serverTLS},
			ErrZoneEnforcementNotConfigured,
		},
		{
			"zones with zone capability",
			base(func(c *Config) { c.Routes[0].Auth.AllowedZones = []string{"control-plane"} }),
			Deps{Auth: &capsChain{caps: zoneCaps}, ServerTLS: serverTLS},
			nil,
		},
		{
			"public routes skip capability checks",
			base(func(c *Config) { c.Routes[0].Auth = AuthRequirements{Mode: AuthModePublic} }),
			Deps{},
			nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkFailClosed(tt.cfg, tt.deps)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("checkFailClosed = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("checkFailClosed = %v, want %v", err, tt.wantErr)
			}
			// Route-level failures wrap in a route ConfigError.
			var ce *ConfigError
			if !errors.As(err, &ce) || ce.Kind != "route" {
				t.Errorf("error = %v, want route ConfigError", err)
			}
		})
	}
}
