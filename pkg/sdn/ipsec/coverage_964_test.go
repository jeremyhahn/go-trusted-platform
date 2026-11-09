package ipsec

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
)

func TestWrappingErrorMessages(t *testing.T) {
	cause := errors.New("boom")
	for _, tt := range []struct {
		err  error
		want string
	}{
		{&FloorError{Err: cause}, "ipsec: fail-closed floor not installed: boom"},
		{&SocketError{Path: "/run/charon.vici", Err: cause}, "ipsec: vici socket /run/charon.vici: boom"},
	} {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
		if !errors.Is(tt.err, cause) {
			t.Errorf("%T does not unwrap to its cause", tt.err)
		}
	}
}

func TestCloseErrorKeepsBothFailures(t *testing.T) {
	cause := errors.New("load failed")
	closeErr := errors.New("socket reset")
	err := &CloseError{Cause: cause, Err: closeErr}

	if got, want := err.Error(), "load failed (close: socket reset)"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Error("CloseError does not match its cause")
	}
	if !errors.Is(err, closeErr) {
		t.Error("CloseError does not match its close failure")
	}
	if errors.Is(err, errInjected) {
		t.Error("CloseError matches an unrelated error")
	}
}

func TestNewFilter(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := validConfig()
		f, err := NewFilter(cfg)
		if err != nil {
			t.Fatalf("NewFilter = %v", err)
		}
		if f.iface != cfg.FabricInterface {
			t.Errorf("iface = %q, want %q", f.iface, cfg.FabricInterface)
		}
		if got, want := f.local, addr(cfg.LocalAddress); got != want {
			t.Errorf("local = %v, want %v", got, want)
		}
	})
	t.Run("not enabled", func(t *testing.T) {
		cfg := validConfig()
		cfg.Enabled = false
		if f, err := NewFilter(cfg); f != nil || !errors.Is(err, config.ErrNotEnabled) {
			t.Fatalf("NewFilter = %v, %v; want %v", f, err, config.ErrNotEnabled)
		}
	})
}

func TestNewEVPNServiceRejectsConfig(t *testing.T) {
	disabled := func(t *testing.T) *config.Config {
		cfg := serviceConfig(t, "tunnel.crl")
		cfg.Enabled = false
		return cfg
	}
	noCRL := func(t *testing.T) *config.Config { return serviceConfig(t) }
	noCert := func(t *testing.T) *config.Config { return serviceConfig(t, "tunnel.crl") }

	for _, tt := range []struct {
		name  string
		cfg   func(*testing.T) *config.Config
		field string
		want  error
	}{
		{"not enabled", disabled, "", config.ErrNotEnabled},
		{"no crl files", noCRL, "crl-files", config.ErrRequired},
		{"no certificate file", noCert, "certificate-file", config.ErrRequired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewEVPNService(tt.cfg(t), &fakeAdmitter{}, &fakeAnchor{}, nil)
			if svc != nil || !errors.Is(err, tt.want) {
				t.Fatalf("NewEVPNService = %v, %v; want %v", svc, err, tt.want)
			}
			if tt.field == "" {
				return
			}
			var cfgErr *config.ConfigError
			if !errors.As(err, &cfgErr) || cfgErr.Field != tt.field {
				t.Fatalf("NewEVPNService error = %v, want a ConfigError on %q", err, tt.field)
			}
		})
	}
}
