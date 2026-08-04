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

package iso

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// defaultModuleKeyRelPath is the default module-signing key location relative
// to the operator's home directory. The key lives OUTSIDE the repository and
// outside any build context — it is mounted read-only into the FIPS kernel
// builder container at build time and must never be committed or baked into
// an image layer.
const defaultModuleKeyRelPath = ".trusted-platform/secure-boot/module-signing-key.pem"

// moduleKeyFlags holds flags for the module-signing-key command.
type moduleKeyFlags struct {
	out          string
	keyBits      int
	commonName   string
	organization string
	country      string
	validYears   int
	force        bool
}

// newModuleSigningKeyCommand creates the module-signing-key subcommand. It
// generates (or reports) the stable platform kernel module-signing key that
// the FIPS kernel build embeds via CONFIG_MODULE_SIG_KEY.
func newModuleSigningKeyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &moduleKeyFlags{}

	cmd := &cobra.Command{
		Use:   "module-signing-key",
		Short: "Generate the stable kernel module-signing key for FIPS kernel builds",
		Long: `Generates the stable platform module-signing key consumed by the FIPS
kernel build (build/docker/fips-kernel-builder) via CONFIG_MODULE_SIG_KEY.

The key is written as a single PEM bundle (PKCS#8 private key followed by a
self-signed certificate) — the exact layout the kernel build expects. The
certificate's public key is embedded in the kernel's builtin trusted keyring
so every in-tree module (CONFIG_MODULE_SIG_ALL) and every out-of-tree module
signed by pkg/modulesign with this key loads under CONFIG_MODULE_SIG_FORCE.

The key is stored OUTSIDE the repository (default:
~/` + defaultModuleKeyRelPath + `) and must be backed up: regenerating it
orphans every module signed with the previous key on already-built kernels.
An existing key is never overwritten unless --force is given.

Examples:
  # Generate the key at the default operator location
  platformctl iso module-signing-key

  # Generate at an explicit path for a build server
  platformctl iso module-signing-key --out /secure/keys/module-signing-key.pem

  # Then build the FIPS kernel with the stable key
  make -C build/docker/fips-kernel-builder build \
    MODULE_SIGNING_KEY=$HOME/` + defaultModuleKeyRelPath,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runModuleSigningKey(cmd, flags)
		},
	}

	cmd.Flags().StringVar(&flags.out, "out", "", "Output path for the key+certificate PEM bundle (default: ~/"+defaultModuleKeyRelPath+")")
	cmd.Flags().IntVar(&flags.keyBits, "key-bits", secureboot.DefaultModuleKeyBits, "RSA key size in bits (minimum 2048)")
	cmd.Flags().StringVar(&flags.commonName, "common-name", secureboot.DefaultModuleKeyCN, "Certificate CommonName")
	cmd.Flags().StringVar(&flags.organization, "organization", "Trusted Platform", "Certificate Organization")
	cmd.Flags().StringVar(&flags.country, "country", "US", "Certificate Country")
	cmd.Flags().IntVar(&flags.validYears, "valid-years", secureboot.DefaultModuleKeyValidYears, "Certificate validity in years")
	cmd.Flags().BoolVar(&flags.force, "force", false, "Overwrite an existing key (DANGEROUS: orphans modules signed with the old key)")

	return cmd
}

// runModuleSigningKey executes the module-signing-key command.
func runModuleSigningKey(cmd *cobra.Command, flags *moduleKeyFlags) error {
	out := flags.out
	if out == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return &WrappedError{Msg: "failed to resolve home directory for default key path (use --out)", Err: err}
		}
		out = filepath.Join(home, filepath.FromSlash(defaultModuleKeyRelPath))
	}

	msk, err := secureboot.GenerateModuleSigningKey(cmd.Context(), &secureboot.ModuleSigningKeyConfig{
		Path:         out,
		KeyBits:      flags.keyBits,
		CommonName:   flags.commonName,
		Organization: flags.organization,
		Country:      flags.country,
		ValidYears:   flags.validYears,
		Force:        flags.force,
	})
	if err != nil {
		return err
	}

	fingerprint := sha256.Sum256(msk.Certificate.Raw)
	printSuccess("Module-signing key generated")
	printInfo(fmt.Sprintf("Path:            %s", msk.Path))
	printInfo(fmt.Sprintf("Subject:         %s", msk.Certificate.Subject.String()))
	printInfo(fmt.Sprintf("Not after:       %s", msk.Certificate.NotAfter.Format("2006-01-02")))
	printInfo(fmt.Sprintf("SHA256:          %s", hex.EncodeToString(fingerprint[:])))
	printInfo("")
	printInfo("Back this key up securely. Build the FIPS kernel with:")
	printInfo(fmt.Sprintf("  make -C build/docker/fips-kernel-builder build MODULE_SIGNING_KEY=%s", msk.Path))

	return nil
}
