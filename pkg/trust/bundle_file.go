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

package trust

import (
	"context"
	"os"
)

// FileCABundleProvider serves the platform CA bundle from a PEM file on
// local disk.
//
// The platform-ca strategy takes its bundle from an injected
// CABundleProvider rather than from configuration, because on the control
// plane the bundle is the platform's own CA (pkg/app injects an adapter
// over it). A node that runs no CA of its own — gatewayd, which reaches
// the control plane over the network and never mints a certificate — has
// no such object to inject, so its platform CA bundle is a file the
// provisioning flow projects onto the node (`/etc/gatewayd/cp-ca.pem`).
// This provider is that file, and it is what makes the internal class
// resolvable off the control plane.
//
// The file is read on every resolution rather than cached at construction:
// a rotated bundle takes effect on the next resolution instead of at the
// next restart, and a resolution that happens before the bundle is
// delivered reports the missing path instead of an empty pool.
type FileCABundleProvider struct {
	path string
}

// Compile-time interface check.
var _ CABundleProvider = (*FileCABundleProvider)(nil)

// NewFileCABundleProvider returns a CABundleProvider reading the PEM
// bundle at path.
func NewFileCABundleProvider(path string) *FileCABundleProvider {
	return &FileCABundleProvider{path: path}
}

// Path returns the configured bundle path.
func (p *FileCABundleProvider) Path() string { return p.path }

// CABundle implements CABundleProvider.
func (p *FileCABundleProvider) CABundle(_ context.Context) ([]byte, error) {
	if p.path == "" {
		return nil, &ErrCABundleFileUnset{}
	}
	bundle, err := os.ReadFile(p.path)
	if err != nil {
		return nil, &ErrCAFileRead{Path: p.path, Err: err}
	}
	if len(bundle) == 0 {
		return nil, ErrCABundleEmpty{}
	}
	return bundle, nil
}
