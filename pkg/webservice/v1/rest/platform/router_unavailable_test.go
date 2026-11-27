package platform

import (
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// wiredConfigUpdater is the minimal ConfigUpdater that wires the
// config-section PUT.
type wiredConfigUpdater struct{}

func (wiredConfigUpdater) UpdateConfig(context.Context, *platformv1.UpdateConfigRequest) (*platformv1.UpdateConfigResponse, error) {
	return &platformv1.UpdateConfigResponse{}, nil
}

func unavailableNames(pr *PlatformRouter) map[string]bool {
	names := map[string]bool{}
	for route, name := range pr.UnavailableRoutes() {
		if route == nil {
			continue
		}
		names[name] = true
	}
	return names
}

// TestUnavailableRoutes_UnwiredWritesAreListed pins that the platform
// writes answering 503 without a backend are reported, so /capabilities
// can mark them not-configured, and drop out once they are wired.
func TestUnavailableRoutes_UnwiredWritesAreListed(t *testing.T) {
	pr, _ := newMountedRouter(t)

	names := unavailableNames(pr)
	for _, want := range []string{"platform-config-update", "platform-shutdown"} {
		if !names[want] {
			t.Fatalf("UnavailableRoutes() = %v, missing %q", names, want)
		}
	}

	pr.SetConfigUpdater(wiredConfigUpdater{})
	pr.SetShutdowner(newFakeShutdowner())
	if got := pr.UnavailableRoutes(); len(got) != 0 {
		t.Fatalf("UnavailableRoutes() after wiring = %v, want empty", got)
	}
}
