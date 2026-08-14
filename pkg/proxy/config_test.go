package proxy

import (
	"errors"
	"testing"
)

// validConfig returns a fully valid multi-element configuration for mutation
// in table tests.
func validConfig() Config {
	return Config{
		Listeners: []ListenerConfig{
			{ID: "main", Address: "127.0.0.1:0", Protocols: []string{ProtocolH1, ProtocolH2}},
			{ID: "alt", Address: "127.0.0.1:0"},
		},
		Routes: []RouteConfig{
			{ID: "api", Hosts: []string{"API.Example.COM"}, PathPrefix: "/api", PoolID: "pool-a", Auth: AuthRequirements{Mode: AuthModeMTLS}},
			{ID: "web", Hosts: []string{"*"}, PathPrefix: "/", PoolID: "pool-b", Auth: AuthRequirements{Mode: AuthModePublic}},
		},
		Pools: []BackendPoolConfig{
			{ID: "pool-a", Backends: []BackendConfig{{URL: "https://10.0.0.1:8443", Weight: 1}}},
			{ID: "pool-b", Backends: []BackendConfig{{URL: "http://10.0.0.2:8080"}}, Balancer: BalancerRoundRobin},
		},
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"valid", func(c *Config) {}, nil},
		{"no listeners", func(c *Config) { c.Listeners = nil }, ErrNoListeners},
		{"listener id required", func(c *Config) { c.Listeners[0].ID = "" }, ErrListenerIDRequired},
		{"duplicate listener id", func(c *Config) { c.Listeners[1].ID = "main" }, ErrDuplicateListenerID},
		{"listener address required", func(c *Config) { c.Listeners[0].Address = "" }, ErrListenerAddressRequired},
		{"unknown protocol h3", func(c *Config) { c.Listeners[0].Protocols = []string{"h3"} }, ErrUnknownProtocol},
		{"unknown protocol junk", func(c *Config) { c.Listeners[1].Protocols = []string{"spdy"} }, ErrUnknownProtocol},
		{"route id required", func(c *Config) { c.Routes[0].ID = "" }, ErrRouteIDRequired},
		{"duplicate route id", func(c *Config) { c.Routes[1].ID = "api" }, ErrDuplicateRouteID},
		{"tcp passthrough unsupported", func(c *Config) { c.Routes[0].PassthroughTCP = true }, ErrTCPPassthroughUnsupported},
		{"empty path prefix", func(c *Config) { c.Routes[0].PathPrefix = "" }, ErrInvalidPathPrefix},
		{"relative path prefix", func(c *Config) { c.Routes[0].PathPrefix = "api" }, ErrInvalidPathPrefix},
		{"auth mode required", func(c *Config) { c.Routes[0].Auth.Mode = "" }, ErrRouteAuthModeRequired},
		{"invalid auth mode", func(c *Config) { c.Routes[0].Auth.Mode = "anonymous" }, ErrInvalidAuthMode},
		{"route pool required", func(c *Config) { c.Routes[0].PoolID = "" }, ErrRoutePoolRequired},
		{"unknown pool id", func(c *Config) { c.Routes[0].PoolID = "missing" }, ErrUnknownPoolID},
		{"pool id required", func(c *Config) { c.Pools[0].ID = ""; c.Routes[0].PoolID = "pool-b" }, ErrPoolIDRequired},
		{"duplicate pool id", func(c *Config) { c.Pools[1].ID = "pool-a" }, ErrDuplicatePoolID},
		{"no backends", func(c *Config) { c.Pools[0].Backends = nil }, ErrNoBackends},
		{"backend url unparsable", func(c *Config) { c.Pools[0].Backends[0].URL = "://bad" }, ErrInvalidBackendURL},
		{"backend url no host", func(c *Config) { c.Pools[0].Backends[0].URL = "http://" }, ErrInvalidBackendURL},
		{"backend scheme ftp", func(c *Config) { c.Pools[0].Backends[0].URL = "ftp://10.0.0.1" }, ErrInvalidBackendScheme},
		{"backend scheme unix", func(c *Config) { c.Pools[0].Backends[0].URL = "unix:///run/x.sock" }, ErrInvalidBackendURL},
		{"negative backend weight", func(c *Config) { c.Pools[0].Backends[0].Weight = -1 }, ErrInvalidBackendWeight},
		{"unknown balancer", func(c *Config) { c.Pools[0].Balancer = "least-conn" }, ErrUnknownBalancer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigValidateNormalizesHosts(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := cfg.Routes[0].Hosts[0]; got != "api.example.com" {
		t.Fatalf("host = %q, want lowercase api.example.com", got)
	}
}

func TestConfigValidateErrorCarriesElementID(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].Auth.Mode = "bogus"
	err := cfg.Validate()
	var cerr *ConfigError
	if !errors.As(err, &cerr) {
		t.Fatalf("error %T, want *ConfigError", err)
	}
	if cerr.Kind != "route" || cerr.ID != "api" {
		t.Fatalf("ConfigError = %+v, want route/api", cerr)
	}
}
