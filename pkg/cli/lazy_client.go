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

package cli

import platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"

// LazyClient connects to the platform on first use, so a command that only
// sometimes needs the platform — a build whose Secure Boot keys may be in the
// KMS or on disk — connects only when it does. The command closes it.
type LazyClient struct {
	flags *CommonFlags
	base  *BaseCommand
}

// NewLazyClient returns a LazyClient for the command's flags.
func NewLazyClient(flags *CommonFlags) *LazyClient {
	return &LazyClient{flags: flags}
}

// Client returns the platform client, connecting on the first call.
func (l *LazyClient) Client() (platform.Client, error) {
	if l.base == nil {
		base, err := NewBaseCommand(l.flags)
		if err != nil {
			return nil, err
		}
		l.base = base
	}
	return l.base.Client(), nil
}

// Close closes the connection if one was opened.
func (l *LazyClient) Close() error {
	if l.base == nil {
		return nil
	}
	return l.base.Close()
}
