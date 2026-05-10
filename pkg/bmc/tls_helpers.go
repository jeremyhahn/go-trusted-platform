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

package bmc

import (
	"crypto/x509"
	"fmt"
	"os"
)

// loadCAPool reads a PEM-encoded CA bundle from path and returns a CertPool
// populated with the contained certificates. Returns a typed error if the
// file cannot be read or contains no parseable certificates.
func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrInvalidConfig{Field: "ca_cert_path", Reason: err.Error()}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, ErrInvalidConfig{
			Field:  "ca_cert_path",
			Reason: fmt.Sprintf("no parseable PEM certificates in %s", path),
		}
	}
	return pool, nil
}
