package proxy

import (
	"errors"
	"net/url"
	"testing"
)

func testBackends(n int) []*backend {
	backends := make([]*backend, 0, n)
	for i := 0; i < n; i++ {
		backends = append(backends, &backend{url: &url.URL{Scheme: "http", Host: "b"}, weight: i})
	}
	return backends
}

func TestNewBalancer(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		wantErr error
	}{
		{"round-robin", BalancerRoundRobin, nil},
		{"empty defaults to round-robin", "", nil},
		{"unknown", "least-conn", ErrUnknownBalancer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := newBalancer(tt.arg)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("newBalancer(%q) err = %v, want %v", tt.arg, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("newBalancer(%q): %v", tt.arg, err)
			}
			if b == nil {
				t.Fatalf("newBalancer(%q) = nil balancer", tt.arg)
			}
		})
	}
}

func TestRoundRobinCycles(t *testing.T) {
	backends := testBackends(3)
	rr := newRoundRobin()
	for i := 0; i < 9; i++ {
		got := rr.Next(backends)
		want := backends[i%3]
		if got != want {
			t.Fatalf("Next() #%d = backend %d, want %d", i, got.weight, want.weight)
		}
	}
}

func TestRoundRobinSingleBackend(t *testing.T) {
	backends := testBackends(1)
	rr := newRoundRobin()
	for i := 0; i < 3; i++ {
		if got := rr.Next(backends); got != backends[0] {
			t.Fatalf("Next() #%d = %v, want the single backend", i, got)
		}
	}
}

func TestRoundRobinEmptyBackends(t *testing.T) {
	rr := newRoundRobin()
	if got := rr.Next(nil); got != nil {
		t.Fatalf("Next(nil) = %v, want nil", got)
	}
}
