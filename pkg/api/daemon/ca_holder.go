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

package daemon

import (
	"sync"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// CAHolder is the one CA the daemon's CA transports serve. daemon.New
// builds it once and hands it to the gRPC CA service and the REST CA
// handlers, so a CA InitCA swaps in is served by both without a restart.
type CAHolder struct {
	mu sync.RWMutex
	ca quicbaasca.CACertificateAuthority
}

// NewCAHolder returns a holder serving ca, which may be nil.
func NewCAHolder(ca quicbaasca.CACertificateAuthority) *CAHolder {
	return &CAHolder{ca: ca}
}

// Get returns the CA held now, or nil. A nil holder holds nothing.
func (h *CAHolder) Get() quicbaasca.CACertificateAuthority {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ca
}

// Set swaps the CA the holder serves.
func (h *CAHolder) Set(ca quicbaasca.CACertificateAuthority) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ca = ca
}

// Initialized reports whether the holder holds an initialised CA.
func (h *CAHolder) Initialized() bool {
	ca := h.Get()
	return ca != nil && ca.IsInitialized()
}
