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

// seal.go implements the canonical "barrier seal" verb.
package barrier

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// sealFlags holds the canonical `barrier seal` flag set.
type sealFlags struct {
	soPin     string
	assumeYes bool
}

// newSealCommand builds the canonical `barrier seal` command.
func newSealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &sealFlags{}
	cmd := &cobra.Command{
		Use:   "seal",
		Short: "Seal the barrier",
		Long: `Seal the barrier to protect platform data at rest.

  --so-pin       Optional. SO PIN verified against the canonical PINBackend.
  -y, --assume-yes  Skip the interactive confirmation prompt.

Sealing renders all subsequently issued I/O against the barrier
encrypted. The barrier must be unsealed before platformd can read or
write the data plane again.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSeal(cmd.InOrStdin(), cmd.OutOrStdout(), getFlags(), f)
		},
	}
	cmd.Flags().StringVar(&f.soPin, "so-pin", "",
		"Security Officer PIN (verified against the canonical PINBackend when configured)")
	cmd.Flags().BoolVarP(&f.assumeYes, "assume-yes", "y", false,
		"Skip the interactive confirmation prompt")
	return cmd
}

// confirmSeal prompts the operator for confirmation. The check is
// case-insensitive on "y" / "yes" to mirror standard CLI ergonomics.
func confirmSeal(stdin io.Reader, stdout io.Writer) (bool, error) {
	if _, err := fmt.Fprint(stdout, "Sealing the barrier will block all data-plane access until unsealed. Proceed? [y/N]: "); err != nil {
		return false, err
	}
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}

// runSeal optionally confirms with the operator, then delegates to
// dispatchSeal.
func runSeal(stdin io.Reader, stdout io.Writer, flags *cli.CommonFlags, f *sealFlags) error {
	if !f.assumeYes {
		ok, err := confirmSeal(stdin, stdout)
		if err != nil {
			return err
		}
		if !ok {
			return ErrSealCancelled{}
		}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	bc, qerr := openBarrierClient(base)
	if qerr != nil {
		return qerr
	}
	return dispatchSeal(newDispatcherFromBase(base, bc))
}
