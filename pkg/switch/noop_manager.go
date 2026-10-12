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

package switchmgmt

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

type noopManager struct{}

// NewNoopManager returns a Manager that performs no operations.
// Used when no physical switch is configured, or for testing.
func NewNoopManager() Manager {
	return &noopManager{}
}

func (n *noopManager) SetPortVLAN(_ context.Context, _ string, _ uint16) error {
	return nil
}

func (n *noopManager) GetPortVLAN(_ context.Context, _ string) (uint16, error) {
	return 0, nil
}

func (n *noopManager) GetPortStatus(_ context.Context, _ string) (*switchwire.PortStatus, error) {
	return &switchwire.PortStatus{}, nil
}

func (n *noopManager) ListPorts(_ context.Context) ([]*switchwire.PortStatus, error) {
	return nil, nil
}

func (n *noopManager) EnablePort(_ context.Context, _ string) error {
	return nil
}

func (n *noopManager) DisablePort(_ context.Context, _ string) error {
	return nil
}

func (n *noopManager) Close() error {
	return nil
}
