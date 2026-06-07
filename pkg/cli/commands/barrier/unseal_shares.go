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

// unseal_shares.go implements the canonical "barrier unseal-shares"
// verb.
package barrier

import (
	"bufio"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// unsealSharesFlags holds the canonical `barrier unseal-shares` flag set.
type unsealSharesFlags struct {
	shares     []string
	sharesFile string
}

// newUnsealSharesCommand builds the canonical `barrier unseal-shares`
// command.
func newUnsealSharesCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	f := &unsealSharesFlags{}
	cmd := &cobra.Command{
		Use:   "unseal-shares",
		Short: "Unseal the barrier with one or more Shamir shares",
		Long: `Unseal the barrier by submitting Shamir shares.

  --share         Repeatable. Submit one share per --share flag.
  --shares-file   Path to a newline-delimited share file. "-" reads from stdin.

Specify --share or --shares-file (not both). The verb sends the shares
in a single BarrierUnsealWithShares RPC.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnsealShares(cmd.InOrStdin(), getFlags(), f)
		},
	}
	cmd.Flags().StringArrayVar(&f.shares, "share", nil,
		"Shamir share to submit (repeatable)")
	cmd.Flags().StringVar(&f.sharesFile, "shares-file", "",
		"Path to a newline-delimited share file (\"-\" reads from stdin)")
	return cmd
}

// loadSharesFromFile reads newline-delimited shares from a path or
// stdin (when path == "-").
func loadSharesFromFile(stdin io.Reader, path string) ([]string, error) {
	var src io.Reader
	if path == "-" {
		src = stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, ErrSharesFileReadFailed{Path: path, Err: err}
		}
		defer f.Close()
		src = f
	}

	scanner := bufio.NewScanner(src)
	// Permit shares larger than the default 64 KiB scanner buffer; Shamir
	// share payloads grow with secret size and the canonical limit on
	// the wire is 1 MiB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, ErrSharesFileReadFailed{Path: path, Err: err}
	}
	return out, nil
}

// resolveShares collapses the flag set into the canonical share slice
// the SDK expects. Returns ErrShareSourcesConflict when both --share
// and --shares-file are supplied, and ErrMissingShares when neither is.
func resolveShares(stdin io.Reader, f *unsealSharesFlags) ([]string, error) {
	hasFlags := len(f.shares) > 0
	hasFile := f.sharesFile != ""
	if hasFlags && hasFile {
		return nil, ErrShareSourcesConflict{}
	}
	if hasFile {
		shares, err := loadSharesFromFile(stdin, f.sharesFile)
		if err != nil {
			return nil, err
		}
		if len(shares) == 0 {
			return nil, ErrMissingShares{}
		}
		return shares, nil
	}
	if !hasFlags {
		return nil, ErrMissingShares{}
	}
	return f.shares, nil
}

// runUnsealShares resolves the share set and delegates to
// dispatchUnsealShares.
func runUnsealShares(stdin io.Reader, flags *cli.CommonFlags, f *unsealSharesFlags) error {
	shares, err := resolveShares(stdin, f)
	if err != nil {
		return err
	}
	base, berr := cli.NewBaseCommand(flags)
	if berr != nil {
		return berr
	}
	defer base.Close()

	bc, qerr := openBarrierClient(base)
	if qerr != nil {
		return qerr
	}
	return dispatchUnsealShares(newDispatcherFromBase(base, bc), shares)
}
