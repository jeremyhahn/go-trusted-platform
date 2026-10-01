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
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
)

// DefaultKeysDir is the on-node directory that holds the PK/KEK/DB
// certificates written by the Secure Boot key manager during installation.
const DefaultKeysDir = "/etc/trusted-platform/secure-boot"

// DefaultUKIPath is the UEFI removable-media boot path of the signed unified
// kernel image on a running node.
const DefaultUKIPath = "/boot/efi/EFI/BOOT/BOOTX64.EFI"

// enrollOptions carries the resolved inputs of the enroll / enforce pipeline.
type enrollOptions struct {
	efivarsDir  string
	keysDir     string
	pkCertPath  string
	kekCertPath string
	dbCertPath  string
	ukiPath     string
	commit      bool
}

// enrollResult reports what the enroll pipeline did (or, on a dry run, would
// have done).
type enrollResult struct {
	DryRun         bool     `json:"dry_run" yaml:"dry_run"`
	EfivarsDir     string   `json:"efivars_dir" yaml:"efivars_dir"`
	UKIPath        string   `json:"uki_path" yaml:"uki_path"`
	UKIVerified    bool     `json:"uki_verified" yaml:"uki_verified"`
	PKSubject      string   `json:"pk_subject" yaml:"pk_subject"`
	KEKSubject     string   `json:"kek_subject" yaml:"kek_subject"`
	DBSubject      string   `json:"db_subject" yaml:"db_subject"`
	Enrolled       bool     `json:"enrolled" yaml:"enrolled"`
	EnrollOrder    []string `json:"enroll_order" yaml:"enroll_order"`
	PostSetupMode  bool     `json:"post_setup_mode" yaml:"post_setup_mode"`
	PostSecureBoot bool     `json:"post_secure_boot" yaml:"post_secure_boot"`
	PostPKPresent  bool     `json:"post_pk_present" yaml:"post_pk_present"`
}

// newEnrollCommand creates the enroll subcommand (dry-run by default).
func newEnrollCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &enrollOptions{}

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll Secure Boot keys into the firmware (dry-run by default)",
		Long: `Enroll the platform PK, KEK, and DB certificates into the running
firmware via efivarfs in the safe order db -> KEK -> PK (PK LAST).

Guards (all run on both dry-run and --commit):
  - efivarfs must be mounted and the firmware in Setup Mode
  - the PK/KEK/DB certificates must load and parse
  - the signed UKI must Authenticode-verify AND its embedded certificate
    must match the DB certificate being enrolled (verify-before-enforce)

Without --commit nothing is written; the command reports exactly what a
commit would do. Writing PK takes the firmware out of Setup Mode and
activates Secure Boot enforcement on the next boot.`,
		Example: `  # Dry-run: run every guard, write nothing
  platformctl secure-boot enroll

  # Enroll keys from the default key directory
  platformctl secure-boot enroll --commit

  # Enroll with explicit certificate paths
  platformctl secure-boot enroll --commit \
    --pk-cert /path/PK.crt --kek-cert /path/KEK.crt --db-cert /path/DB.crt`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			result, err := runEnroll(cmd.Context(), opts, nil)
			if err != nil {
				return err
			}
			return printEnrollResult(flags, result)
		},
	}

	addEnrollFlags(cmd, opts)
	return cmd
}

// addEnrollFlags registers the flags shared by enroll and enforce.
func addEnrollFlags(cmd *cobra.Command, opts *enrollOptions) {
	cmd.Flags().StringVar(&opts.efivarsDir, "efivars", uefi.EfivarsPath,
		"efivarfs directory (override for rehearsal against a fixture directory)")
	cmd.Flags().StringVar(&opts.keysDir, "keys-dir", DefaultKeysDir,
		"directory holding PK.crt, KEK.crt, and DB.crt")
	cmd.Flags().StringVar(&opts.pkCertPath, "pk-cert", "", "explicit PK certificate path (overrides --keys-dir)")
	cmd.Flags().StringVar(&opts.kekCertPath, "kek-cert", "", "explicit KEK certificate path (overrides --keys-dir)")
	cmd.Flags().StringVar(&opts.dbCertPath, "db-cert", "", "explicit DB certificate path (overrides --keys-dir)")
	cmd.Flags().StringVar(&opts.ukiPath, "uki", DefaultUKIPath, "path to the signed unified kernel image")
	cmd.Flags().BoolVar(&opts.commit, "commit", false,
		"actually write the Secure Boot variables (default is dry-run)")
}

// runEnroll executes the guarded enrollment pipeline. When verifier is nil
// the production Authenticode verifier is built from the DB certificate;
// tests inject their own uefi.UKIVerifier.
func runEnroll(ctx context.Context, opts *enrollOptions, verifier uefi.UKIVerifier) (*enrollResult, error) {
	logger := logging.DefaultLogger()

	// Gate 1: efivarfs must be present and readable.
	status, err := uefi.ReadSecureBootStatusFromDir(opts.efivarsDir)
	if err != nil {
		return nil, err
	}

	// Gate 2: raw key enrollment is only permitted in Setup Mode.
	if !status.SetupMode {
		return nil, uefi.ErrNotSetupMode
	}

	// Gate 3: the certificates must load and parse.
	pkCert, kekCert, dbCert, err := loadEnrollCertificates(opts)
	if err != nil {
		return nil, err
	}

	// Gate 4: verify-before-enforce. The signed UKI must exist, carry a valid
	// Authenticode signature, and be signed by exactly the DB certificate
	// about to be enrolled. This is the brick guard: only a UKI the enrolled
	// db will accept may proceed to enrollment.
	if _, statErr := os.Stat(opts.ukiPath); statErr != nil {
		return nil, ErrUKINotFound{Path: opts.ukiPath}
	}
	if verifier == nil {
		verifier = newUKIVerifier(ctx, logger)
	}
	if err := uefi.VerifySignedUKI(verifier, opts.ukiPath, dbCert, logger); err != nil {
		return nil, err
	}

	result := &enrollResult{
		DryRun:      !opts.commit,
		EfivarsDir:  opts.efivarsDir,
		UKIPath:     opts.ukiPath,
		UKIVerified: true,
		PKSubject:   pkCert.Subject.String(),
		KEKSubject:  kekCert.Subject.String(),
		DBSubject:   dbCert.Subject.String(),
		EnrollOrder: []string{"db", "KEK", "PK"},
	}

	if !opts.commit {
		return result, nil
	}

	// Commit: write db -> KEK -> PK. PK LAST — Secure Boot only activates
	// when PK is written, so any earlier failure leaves the node bootable.
	if err := uefi.EnrollKeysToEfivarsDir(ctx, opts.efivarsDir, pkCert, kekCert, dbCert,
		uefi.NewEFITime(time.Now())); err != nil {
		return nil, err
	}
	result.Enrolled = true

	// Read back the resulting firmware state.
	post, err := uefi.ReadSecureBootStatusFromDir(opts.efivarsDir)
	if err != nil {
		return nil, err
	}
	result.PostSetupMode = post.SetupMode
	result.PostSecureBoot = post.SecureBoot
	result.PostPKPresent = post.PK.Present
	return result, nil
}

// loadEnrollCertificates loads the PK, KEK, and DB certificates from the
// explicit per-role paths or the shared keys directory.
func loadEnrollCertificates(opts *enrollOptions) (pk, kek, db *x509.Certificate, err error) {
	pk, err = loadRoleCertificate("PK", opts.pkCertPath, opts.keysDir, "PK.crt")
	if err != nil {
		return nil, nil, nil, err
	}
	kek, err = loadRoleCertificate("KEK", opts.kekCertPath, opts.keysDir, "KEK.crt")
	if err != nil {
		return nil, nil, nil, err
	}
	db, err = loadRoleCertificate("DB", opts.dbCertPath, opts.keysDir, "DB.crt")
	if err != nil {
		return nil, nil, nil, err
	}
	return pk, kek, db, nil
}

// loadRoleCertificate loads one PEM certificate from the explicit path when
// set, otherwise from dir/filename.
func loadRoleCertificate(role, explicitPath, dir, filename string) (*x509.Certificate, error) {
	path := explicitPath
	if path == "" {
		path = filepath.Join(dir, filename)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrCertificateLoad{Role: role, Path: path, Cause: err}
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrCertificateLoad{Role: role, Path: path, Cause: ErrNotPEMCertificate{Path: path}}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrCertificateLoad{Role: role, Path: path, Cause: err}
	}
	return cert, nil
}

// printEnrollResult renders an enroll result on the configured printer.
func printEnrollResult(flags *cli.CommonFlags, result *enrollResult) error {
	printer := cli.NewPrinter(flags.OutputFormat, flags.NoColor)
	if flags.OutputFormat != cli.OutputFormatTable {
		return printer.Print(result)
	}
	if result.DryRun {
		printer.PrintWarning("DRY RUN — no variables were written (pass --commit to enroll)")
	}
	printer.PrintKeyValue("Efivars", result.EfivarsDir)
	printer.PrintKeyValue("UKI", result.UKIPath+" (verified against DB certificate)")
	printer.PrintKeyValue("PK", result.PKSubject)
	printer.PrintKeyValue("KEK", result.KEKSubject)
	printer.PrintKeyValue("DB", result.DBSubject)
	if result.Enrolled {
		printer.PrintSuccess("Secure Boot keys enrolled (db -> KEK -> PK)")
		printer.PrintKeyValue("SetupMode (post)", boolWord(result.PostSetupMode))
		printer.PrintKeyValue("SecureBoot (post)", boolWord(result.PostSecureBoot))
	}
	return nil
}
