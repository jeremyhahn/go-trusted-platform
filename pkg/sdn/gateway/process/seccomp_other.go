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

//go:build !amd64 && !arm64

package process

import "runtime"

// nativeSeccompTable has no table on this architecture. The child refuses
// to start rather than run without its filter.
func nativeSeccompTable() (seccompTable, error) {
	return seccompTable{}, &ErrSeccompUnsupportedArch{Arch: runtime.GOARCH}
}
