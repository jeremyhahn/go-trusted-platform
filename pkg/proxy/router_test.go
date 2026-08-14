package proxy

import "testing"

// makeRoute builds a bare CompiledRoute for router tests.
func makeRoute(id string, hosts []string, prefix string) *CompiledRoute {
	return &CompiledRoute{cfg: RouteConfig{ID: id, Hosts: hosts, PathPrefix: prefix}}
}

func testTable() *routeTable {
	return buildRouteTable([]*CompiledRoute{
		makeRoute("root", []string{"*"}, "/"),
		makeRoute("api", []string{"api.example.com"}, "/api"),
		makeRoute("api-v2", []string{"api.example.com"}, "/api/v2"),
		makeRoute("wild-metrics", []string{"*"}, "/metrics"),
		makeRoute("no-hosts", nil, "/orphan"),
	})
}

func TestRouteTableMatch(t *testing.T) {
	table := testTable()
	tests := []struct {
		name   string
		host   string
		path   string
		wantID string
	}{
		{"longest prefix wins", "api.example.com", "/api/v2/things", "api-v2"},
		{"shorter prefix", "api.example.com", "/api/v1/things", "api"},
		{"exact prefix boundary", "api.example.com", "/api", "api"},
		{"segment boundary not matched", "api.example.com", "/apiary", "root"},
		{"exact host beats wildcard", "api.example.com", "/api/v2", "api-v2"},
		{"wildcard fallback for unmatched host", "other.example.com", "/metrics", "wild-metrics"},
		{"wildcard fallback when exact host misses path", "api.example.com", "/metrics", "wild-metrics"},
		{"port stripped", "api.example.com:8443", "/api", "api"},
		{"host case-insensitive", "API.Example.COM", "/api", "api"},
		{"host case-insensitive with port", "API.EXAMPLE.COM:443", "/api/v2/x", "api-v2"},
		{"empty hosts treated as wildcard", "anything.example", "/orphan/x", "no-hosts"},
		{"root catch-all", "anything.example", "/anywhere", "root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cr := table.match(tt.host, tt.path)
			if cr == nil {
				t.Fatalf("match(%q, %q) = nil, want %q", tt.host, tt.path, tt.wantID)
			}
			if cr.cfg.ID != tt.wantID {
				t.Fatalf("match(%q, %q) = %q, want %q", tt.host, tt.path, cr.cfg.ID, tt.wantID)
			}
		})
	}
}

func TestRouteTableMatchNoMatch(t *testing.T) {
	table := buildRouteTable([]*CompiledRoute{
		makeRoute("api", []string{"api.example.com"}, "/api"),
	})
	tests := []struct {
		name string
		host string
		path string
	}{
		{"unknown host no wildcard", "other.example.com", "/api"},
		{"known host unmatched path", "api.example.com", "/other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if cr := table.match(tt.host, tt.path); cr != nil {
				t.Fatalf("match(%q, %q) = %q, want nil", tt.host, tt.path, cr.cfg.ID)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"Example.COM", "example.com"},
		{"example.com:8443", "example.com"},
		{"EXAMPLE.com:443", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
		{"[::1]", "[::1]"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeHost(tt.in); got != tt.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMatchPrefix(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/anything", "/", true},
		{"/api", "/api", true},
		{"/api/v1", "/api", true},
		{"/apiary", "/api", false},
		{"/other", "/api", false},
		{"/", "/api", false},
	}
	for _, tt := range tests {
		if got := matchPrefix(tt.path, tt.prefix); got != tt.want {
			t.Errorf("matchPrefix(%q, %q) = %v, want %v", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestCompiledRouteConfig(t *testing.T) {
	cr := makeRoute("api", []string{"api.example.com"}, "/api")
	cfg := cr.Config()
	if cfg.ID != "api" || cfg.PathPrefix != "/api" {
		t.Fatalf("Config() = %+v, want id api prefix /api", cfg)
	}
	// Mutating the returned copy must not affect the compiled route.
	cfg.ID = "changed"
	if cr.cfg.ID != "api" {
		t.Fatal("Config() must return a copy")
	}
}
