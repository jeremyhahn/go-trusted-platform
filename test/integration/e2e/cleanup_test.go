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

//go:build integration

package e2e_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestCleanupToleratesUnbuiltVMs covers a setup that failed before any VM
// was built: Cleanup used to pass the nil *qemu.VM through an interface{},
// miss the nil check and panic in IsRunning (#949).
func TestCleanupToleratesUnbuiltVMs(t *testing.T) {
	infra := &TestInfrastructure{
		Config: DefaultTestConfig(),
		Logger: logging.DefaultLogger(),
	}

	require.NotPanics(t, func() { Cleanup(t, infra) })
}

// TestCleanupToleratesNilInfrastructure covers SetupTestInfrastructure
// returning no infrastructure at all.
func TestCleanupToleratesNilInfrastructure(t *testing.T) {
	require.NotPanics(t, func() { Cleanup(t, nil) })
}
