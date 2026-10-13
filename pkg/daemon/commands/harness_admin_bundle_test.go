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

//go:build !integration

package commands

import "testing"

// TestHarnessAdminBundle_AbsentFromProductionBuild asserts a production
// build carries no path that mints an admin client bundle: the hook only
// the integration build tag sets is nil here, so applyDaemonTLSIdentity
// writes no client-bundle.pem.
func TestHarnessAdminBundle_AbsentFromProductionBuild(t *testing.T) {
	if harnessAdminBundle != nil {
		t.Fatal("a production build must not carry the integration harness admin bundle hook")
	}
}
