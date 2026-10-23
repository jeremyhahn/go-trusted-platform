// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package commands

import (
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
)

// TestPlatformSDKBackendSources_WithoutStorage verifies an app whose storage
// is not the QuicBaaS SDK yields no client, which the wiring then refuses.
func TestPlatformSDKBackendSources_WithoutStorage(t *testing.T) {
	for name, a := range map[string]*app.App{"nil app": nil, "no storage": {}} {
		t.Run(name, func(t *testing.T) {
			src := platformSDKBackendSources(a)
			if src.SDK != nil || src.Admin != nil {
				t.Errorf("sources = %+v, want none", src)
			}
		})
	}
}

func TestServeStartup_WrapsSDKBackendError(t *testing.T) {
	err := ErrServeStartup{Phase: "SDK backends", Cause: appbackends.ErrCeremonyBackendRequiresSDK{}}
	if !strings.Contains(err.Error(), "SDK backends: ceremony") {
		t.Errorf("message %q does not name the phase and the cause", err.Error())
	}
}
