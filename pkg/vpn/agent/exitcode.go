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

package agent

import (
	"errors"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// Exit codes of the client verbs (docs/vpn/cli.md).
const (
	ExitOK               = 0
	ExitFailure          = 1
	ExitRefused          = 4
	ExitPostureViolation = 5
	ExitNotConnected     = 6
)

// refusalExitCodes overrides ExitRefused for the classes that have their own
// code.
var refusalExitCodes = map[gwvpn.RefusalClass]int{
	gwvpn.RefusalPostureViolation: ExitPostureViolation,
}

// ExitCode maps a client verb's error to its exit code: every gateway
// refusal is ExitRefused unless its class has its own code, holding no lease
// is ExitNotConnected, and anything else is ExitFailure.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var refused *RefusedError
	if errors.As(err, &refused) {
		if code, ok := refusalExitCodes[refused.Class]; ok {
			return code
		}
		return ExitRefused
	}
	var notConnected *ErrNotConnected
	if errors.As(err, &notConnected) {
		return ExitNotConnected
	}
	return ExitFailure
}
