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
	"crypto/tls"
	"errors"
	"sync/atomic"
)

// CertReloader provides lock-free TLS certificate hot-reload using an atomic
// pointer. It is designed to be used with tls.Config.GetCertificate for
// seamless certificate rotation without restarting listeners.
type CertReloader struct {
	current atomic.Pointer[tls.Certificate]
}

// NewCertReloader creates a CertReloader initialized with the provided TLS
// certificate. It returns ErrCertReloadFailed if initial is nil.
func NewCertReloader(initial *tls.Certificate) (*CertReloader, error) {
	if initial == nil {
		return nil, ErrCertReloadFailed{
			Cause: errors.New("initial certificate cannot be nil"),
		}
	}
	r := &CertReloader{}
	r.current.Store(initial)
	return r, nil
}

// GetCertificateFunc returns a closure suitable for assignment to
// tls.Config.GetCertificate. The closure reads the current certificate from
// the atomic pointer, providing lock-free access for concurrent TLS
// handshakes.
func (r *CertReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return r.current.Load(), nil
	}
}

// Reload atomically swaps the current certificate with newCert. It returns
// ErrCertReloadFailed if newCert is nil.
func (r *CertReloader) Reload(newCert *tls.Certificate) error {
	if newCert == nil {
		return ErrCertReloadFailed{
			Cause: errors.New("new certificate cannot be nil"),
		}
	}
	r.current.Store(newCert)
	return nil
}

// Current returns the current TLS certificate for inspection.
func (r *CertReloader) Current() *tls.Certificate {
	return r.current.Load()
}
