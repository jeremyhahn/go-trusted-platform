//go:build integration

package luks

import (
	"context"
	"errors"
	"testing"
)

// TestRESTAdapterPresentsHarnessBearer pins that the REST adapter presents
// the harness admin session's bearer, and that a bearer failure surfaces as
// ErrConnectionFailed before any dial.
func TestRESTAdapterPresentsHarnessBearer(t *testing.T) {
	if NewRESTAdapter().bearer == nil {
		t.Fatal("REST adapter has no bearer source")
	}

	sentinel := errors.New("bearer unavailable")
	adapter := NewRESTAdapter()
	adapter.bearer = func(context.Context) (string, error) { return "", sentinel }
	err := adapter.Setup(context.Background())
	var connErr ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Fatalf("Setup error = %v, want ErrConnectionFailed", err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Setup error = %v, want the bearer error", err)
	}
}
