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

package noise

import (
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// testBundler is a minimal BundleProvider for testing.
type testBundler struct {
	data []byte
	err  error
}

// CABundle returns the configured test bundle data or error.
func (b *testBundler) CABundle() ([]byte, error) {
	return b.data, b.err
}

func testConfig() *bootstrap.NoiseServerConfig {
	return &bootstrap.NoiseServerConfig{
		Enabled:        true,
		ListenAddr:     "127.0.0.1:0",
		MaxConnections: 10,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
	}
}

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

func testBundlerWithData() *testBundler {
	return &testBundler{
		data: []byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"),
	}
}
