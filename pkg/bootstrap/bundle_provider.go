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

package bootstrap

import (
	"crypto/x509"

	"github.com/jeremyhahn/go-truststrap/pkg/truststrap"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Compile-time interface check.
var _ truststrap.BundleProvider = (*CABundleAdapter)(nil)

// CABundler provides access to a CA certificate bundle filtered by store type
// and key algorithm.
type CABundler interface {
	CABundle(storeType xkmssdk.StoreType, keyAlgorithm x509.PublicKeyAlgorithm) ([]byte, error)
}

// CABundleAdapter adapts a CertificateAuthority to the truststrap BundleProvider
// interface by calling CABundle with default parameters that return the full bundle.
type CABundleAdapter struct {
	ca CABundler
}

// NewCABundleAdapter creates a new CABundleAdapter that wraps the given CA.
func NewCABundleAdapter(ca CABundler) *CABundleAdapter {
	return &CABundleAdapter{ca: ca}
}

// CABundle returns the full CA certificate bundle as PEM bytes.
func (a *CABundleAdapter) CABundle() ([]byte, error) {
	if a.ca == nil {
		return nil, ErrCABundleEmpty{}
	}
	return a.ca.CABundle(xkmssdk.StoreUnknown, 0)
}
