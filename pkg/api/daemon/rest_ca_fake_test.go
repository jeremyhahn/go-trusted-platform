// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"
	"crypto/x509"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// fakeRESTCA is the mock CA exposing the xkmsca.TCGCA surface SetCAHandlers
// needs. It carries no build constraint: the codec-tagged REST CA tests and
// the untagged installer-scope tests both use it.
type fakeRESTCA struct {
	xkmsca.TCGCA // embed for any methods we don't override
}

func (f *fakeRESTCA) Identity() string                                { return "Test CA" }
func (f *fakeRESTCA) IsInitialized() bool                             { return true }
func (f *fakeRESTCA) DefaultKeyAlgorithm() x509.PublicKeyAlgorithm    { return x509.ECDSA }
func (f *fakeRESTCA) DefaultValidityPeriod() int                      { return 365 }
func (f *fakeRESTCA) TrustedRoot() (*x509.Certificate, error)         { return nil, nil }
func (f *fakeRESTCA) TrustedIntermediate() (*x509.Certificate, error) { return nil, nil }
func (f *fakeRESTCA) IssueCertificate(_ context.Context, req *xkmsca.CACertificateRequest) (*xkmsca.IssuedCertificate, error) {
	return nil, nil
}

func (f *fakeRESTCA) RevokeCert(_ context.Context, _ *x509.Certificate, _ xkmsca.RevokeOptions) error {
	return nil
}
func (f *fakeRESTCA) CABundle() ([]byte, error) { return []byte{}, nil }
func (f *fakeRESTCA) CABundleFiltered(xkmssdk.StoreType, x509.PublicKeyAlgorithm) ([]byte, error) {
	return []byte{}, nil
}
func (f *fakeRESTCA) ParseBundle([]byte) ([]*x509.Certificate, error) { return nil, nil }
func (f *fakeRESTCA) CertStore() xkmssdk.CertStore                    { return nil }
