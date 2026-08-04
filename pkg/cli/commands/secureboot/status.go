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

package secureboot

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// newStatusCommand creates the read-only status subcommand.
func newStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var efivarsDir string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report firmware Secure Boot state (read-only)",
		Long: `Read the firmware Secure Boot state from efivarfs.

Reports SetupMode, SecureBoot, UserMode, and the contents of the PK, KEK,
db, and dbx signature databases (certificate subjects and hash counts).
This command performs no writes.`,
		Example: `  # Report firmware Secure Boot state
  platformctl secure-boot status

  # JSON output
  platformctl secure-boot status -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(getFlags(), efivarsDir)
		},
	}

	cmd.Flags().StringVar(&efivarsDir, "efivars", uefi.EfivarsPath,
		"efivarfs directory to read (override for rehearsal against a fixture directory)")
	return cmd
}

// runStatus reads and prints the firmware Secure Boot state.
func runStatus(flags *cli.CommonFlags, efivarsDir string) error {
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)

	status, err := uefi.ReadSecureBootStatusFromDir(efivarsDir)
	if err != nil {
		return err
	}

	if flags.OutputFormat != cli.OutputFormatTable {
		return printer.Print(status)
	}

	printer.PrintKeyValue("Efivars", efivarsDir)
	printer.PrintKeyValue("SetupMode", boolWord(status.SetupMode))
	printer.PrintKeyValue("SecureBoot", boolWord(status.SecureBoot))
	printer.PrintKeyValue("UserMode", boolWord(status.UserMode))
	for _, db := range []uefi.SignatureDatabase{status.PK, status.KEK, status.DB, status.DBX} {
		printer.PrintKeyValue(db.Name, describeDatabase(db))
	}
	return nil
}

// describeDatabase renders a one-line summary of a signature database.
func describeDatabase(db uefi.SignatureDatabase) string {
	if !db.Present {
		return "absent"
	}
	parts := []string{fmt.Sprintf("%d certificate(s)", db.Certificates)}
	if db.Hashes > 0 {
		parts = append(parts, fmt.Sprintf("%d hash(es)", db.Hashes))
	}
	if db.Other > 0 {
		parts = append(parts, fmt.Sprintf("%d other", db.Other))
	}
	if len(db.Subjects) > 0 {
		parts = append(parts, "["+strings.Join(db.Subjects, "; ")+"]")
	}
	return strings.Join(parts, ", ")
}

// boolWord renders a boolean as enabled/disabled for table output.
func boolWord(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}
