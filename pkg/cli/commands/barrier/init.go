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

// init.go implements the canonical "barrier init" verb. The verb is
// a real (no-op-free) dispatcher per docs/08-bootstrap-auth-architecture.md
// §6 and is part of the 9-verb tree shared with qrdbctl, xkmsctl, and
// quicbaas. The root "platformctl init" command remains an
// operator-friendly aggregate that internally invokes "barrier init"
// alongside CA, admin-cert, and role setup.
package barrier

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Strategy tokens for the canonical --barrier-strategy flag.
const (
	StrategyNone       = "none"
	StrategyPassphrase = "passphrase"
	StrategyShamir     = "shamir"
)

// allowedInitStrategies is the canonical strategy set for `barrier init`.
// `shamir` is also a valid init verb but operators are pushed to
// `init-shamir` to surface the threshold/total flags up-front.
var allowedInitStrategies = map[string]struct{}{
	StrategyNone:       {},
	StrategyPassphrase: {},
	StrategyShamir:     {},
}

// initFlags holds the canonical `barrier init` flag set.
type initFlags struct {
	strategy string
	secret   string
	soPin    string
	userPin  string
}

// newInitCommand builds the canonical `barrier init` command.
func newInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &initFlags{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the barrier with the chosen strategy",
		Long: `Initialize the barrier with the chosen sealing strategy.

  --barrier-strategy  Required. One of: none, passphrase, shamir.
  --passphrase        Required for passphrase / shamir. Forbidden for none.
  --so-pin            Optional. Sets the Security Officer PIN on the
                      canonical PINBackend. Requires --user-pin (dual-control).
                      Forbidden for --barrier-strategy=none.
  --user-pin          Optional. Sets the user PIN. Requires --so-pin.
                      Forbidden for --barrier-strategy=none.

The verb dispatches to the QuicBaaS daemon via the platform SDK
Client.QuicBaaS().Security().Barrier() surface and is part of the
canonical 9-verb tree.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInit(getFlags(), f)
		},
	}
	cmd.Flags().StringVar(&f.strategy, "barrier-strategy", "",
		"Barrier strategy: none | passphrase | shamir (required)")
	cmd.Flags().StringVar(&f.secret, "passphrase", "",
		"Wrapping passphrase (required for passphrase / shamir; forbidden for none)")
	cmd.Flags().StringVar(&f.soPin, "so-pin", "",
		"Security Officer PIN (requires --user-pin; forbidden when --barrier-strategy=none)")
	cmd.Flags().StringVar(&f.userPin, "user-pin", "",
		"User PIN (requires --so-pin; forbidden when --barrier-strategy=none)")
	return cmd
}

// validateInitFlags applies the canonical flag-combination rules. The
// rules are pure functions of the flag set so they can be unit-tested
// without a live daemon.
func validateInitFlags(f *initFlags) error {
	if _, ok := allowedInitStrategies[f.strategy]; !ok {
		return ErrInvalidBarrierStrategy{Strategy: f.strategy}
	}
	if f.strategy == StrategyNone {
		if f.secret != "" {
			return ErrSecretNotAllowed{Strategy: f.strategy}
		}
		if f.soPin != "" {
			return PINsNotAllowedError{Flag: "so-pin", Strategy: f.strategy}
		}
		if f.userPin != "" {
			return PINsNotAllowedError{Flag: "user-pin", Strategy: f.strategy}
		}
		return nil
	}
	if f.secret == "" {
		return ErrSecretRequired{Strategy: f.strategy}
	}
	if f.userPin != "" && f.soPin == "" {
		return ErrUserPinRequiresSOPin{}
	}
	if f.soPin != "" && f.userPin == "" {
		return ErrSOPinRequiresUserPin{}
	}
	return nil
}

// runInit validates the flag set, opens the SDK connection, and
// delegates the RPC + rendering to dispatchInit.
func runInit(flags *cli.CommonFlags, f *initFlags) error {
	if err := validateInitFlags(f); err != nil {
		return err
	}
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	bc, err := openBarrierClient(base)
	if err != nil {
		return err
	}
	return dispatchInit(newDispatcherFromBase(base, bc), f)
}
