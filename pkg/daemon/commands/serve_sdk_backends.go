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
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
)

// platformSDKBackendSources returns the SDK backend sources for the running
// platform, or none when there is no platform, which
// appbackends.WireSDKBackends then refuses.
func platformSDKBackendSources(a *app.App) appbackends.SDKBackendSources {
	if a == nil {
		return appbackends.SDKBackendSources{}
	}
	return appbackends.PlatformSDKBackendSources(a.QuicBaaSSDKClient(), a.CA, appbackends.PlatformAdminIdentity(a))
}
