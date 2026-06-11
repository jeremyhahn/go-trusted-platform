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

package trust

import (
	xkmsresolver "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/trust/resolver"
)

// InstallToSystemTrust writes the PEM-encoded CA bundle to the given
// certificate path, creating parent directories as needed. The caller is
// responsible for running OS-specific trust store update commands (e.g.,
// update-ca-certificates) afterward.
//
// Implementation is delegated to the canonical xkms resolver via the
// QuicBaaS SDK re-export.
func InstallToSystemTrust(bundlePEM []byte, certPath string) error {
	return xkmsresolver.InstallToSystemTrust(bundlePEM, certPath)
}
