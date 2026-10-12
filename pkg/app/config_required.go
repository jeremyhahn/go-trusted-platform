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

package app

import (
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// Dotted keys checkRequiredConfig names in its errors.
const (
	quicbaasTransportKey         = "quicbaas.transport"
	quicbaasSPIFFETrustDomainKey = "quicbaas.spiffe-trust-domain"
)

// checkRequiredConfig rejects, at config load, a config the QuicBaaS
// factory would refuse once App.Init reached it: the embedded server needs
// quicbaas.spiffe-trust-domain, and an absent quicbaas: section selects the
// embedded server without one. The error names the file and the key.
func checkRequiredConfig(file string, qc *quicbaas.Config) error {
	err := qc.ValidateSPIFFETrustDomain()
	if err == nil {
		return nil
	}
	key := quicbaasSPIFFETrustDomainKey
	var transportErr quicbaas.ErrInvalidTransport
	if errors.As(err, &transportErr) {
		key = quicbaasTransportKey
	}
	return &config.ErrInvalidConfigKey{File: file, Key: key, Err: err}
}
