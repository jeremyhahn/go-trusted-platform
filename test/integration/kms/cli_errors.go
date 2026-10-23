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

//go:build integration

package kms

import "fmt"

// ErrCLINoFlag is returned, before platformctl runs, when an option has no
// documented platformctl flag (docs/kms/cli.md), so the CLI transport cannot
// send it. The other transports accept the option.
type ErrCLINoFlag struct {
	Operation string
	Flag      string
}

func (e ErrCLINoFlag) Error() string {
	return fmt.Sprintf("%s: platformctl has no %s flag (docs/kms/cli.md)", e.Operation, e.Flag)
}
