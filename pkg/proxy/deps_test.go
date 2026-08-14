package proxy

import (
	"crypto/tls"
	"errors"
	"testing"
)

func TestDepsWithDefaults(t *testing.T) {
	d := Deps{}.withDefaults()
	if d.Audit == nil {
		t.Error("Audit not defaulted")
	}
	if _, ok := d.Audit.(noopSink); !ok {
		t.Errorf("Audit = %T, want noopSink", d.Audit)
	}
	if d.Logger == nil {
		t.Error("Logger not defaulted")
	}
}

func TestDepsWithDefaultsPreservesProvided(t *testing.T) {
	sink := &captureSink{}
	logger := testLogger()
	d := Deps{Audit: sink, Logger: logger}.withDefaults()
	if d.Audit != AuditSink(sink) {
		t.Error("provided Audit replaced")
	}
	if d.Logger != logger {
		t.Error("provided Logger replaced")
	}
}

func TestCheckFailClosed(t *testing.T) {
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13}
	publicCfg := publicConfig("http://10.0.0.1:8080")
	authCfg := authConfig("http://10.0.0.1:8080")
	trustCfg := publicConfig("https://10.0.0.1:8443")
	trustCfg.Pools[0].TLS.TrustClass = "internal"
	tests := []struct {
		name    string
		cfg     *Config
		deps    Deps
		wantErr error
	}{
		{"public needs nothing", &publicCfg, Deps{}, nil},
		{"auth without chain", &authCfg, Deps{ServerTLS: serverTLS}, ErrAuthChainRequired},
		{"auth without tls", &authCfg, Deps{Auth: &fakeAuth{}}, ErrTLSRequiredForAuth},
		{"auth fully composed", &authCfg, Deps{Auth: &fakeAuth{}, ServerTLS: serverTLS}, nil},
		{"trust class without resolver", &trustCfg, Deps{}, ErrTrustResolverRequired},
		{"trust class with resolver", &trustCfg, Deps{Trust: &fakeTrust{}}, nil},
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
		})
	}
}
