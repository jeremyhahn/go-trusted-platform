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

// init_helpers.go preserves the pure-function helpers that the legacy
// "barrier init" handler (now collapsed into the canonical root init)
// exposed for unit testing. Per
// docs/08-bootstrap-auth-architecture.md §6 the command path is gone;
// the helpers stay because they encode the validation and rendering
// rules that the canonical init must continue to satisfy.
package barrier

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	barriersvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/barrier"
)

// validateInitParams checks that the supplied (secret, threshold,
// shares) tuple is internally consistent. Used by the canonical init
// validator and by legacy unit tests that exercise the same rules.
func validateInitParams(secret string, threshold, shares int32) error {
	// Shamir mode: threshold >= 2, shares >= threshold
	if threshold >= 2 {
		if shares < threshold {
			return ErrInvalidThreshold{Threshold: threshold, Shares: shares}
		}
		return nil
	}
	if secret == "" {
		return ErrMissingSecret{}
	}
	return nil
}

// printInitTable renders the barrier init result as a human-readable
// table. Preserved for legacy unit tests; the canonical init renderer
// shares the same shape.
func printInitTable(printer *cli.Printer, result *barriersvc.InitResult) error {
	printer.PrintSuccess("Barrier initialized successfully")
	fmt.Println()

	printer.PrintKeyValue("Strategy", formatStrategy(result.Strategy))

	if result.InitializedAt != nil {
		printer.PrintKeyValue("Initialized At", result.InitializedAt.String())
	}

	if result.RootToken != "" {
		printer.PrintKeyValue("Root Token", result.RootToken)
	}

	fmt.Println()

	if len(result.UnsealKeys) > 0 {
		printer.PrintWarning("Store the following unseal keys securely. They are only shown once.")
		fmt.Println()

		for i, key := range result.UnsealKeys {
			printer.PrintKeyValue(fmt.Sprintf("Unseal Key %d", i+1), key)
		}
	}

	return nil
}
