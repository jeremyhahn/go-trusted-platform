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

package install

import (
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"strings"

	"github.com/spf13/cobra"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	_ "github.com/jeremyhahn/go-trusted-platform/pkg/installer/alpine" // Register Alpine FIPS installer
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// ukiRebuildFlags holds flags for the uki-rebuild command.
type ukiRebuildFlags struct {
	kver       string
	config     string
	espUKIPath string
	verbose    bool
	debug      bool
}

// newUKIRebuildCommand creates the uki-rebuild subcommand. It runs ON the
// installed/booted node — invoked by the kernel-update hook
// (/etc/kernel/install.d/90-trusted-platform-uki.install) — to rebuild and
// re-sign the UKI after a kernel package change.
//
// This is a LOCAL node-maintenance verb, not a daemon RPC: it rebuilds the UKI
// on the local filesystem and atomically swaps it into the ESP. It is therefore
// exempt from the 5-protocol service treatment, but it still reaches all crypto
// through the SDK (remote DB hash-signing goes through the platform SDK client).
func newUKIRebuildCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmdFlags := &ukiRebuildFlags{}

	cmd := &cobra.Command{
		Use:   "uki-rebuild",
		Short: "Rebuild and re-sign the Unified Kernel Image after a kernel update",
		Long: `Rebuild and re-sign the Unified Kernel Image (UKI) on the installed node.

This command runs on the booted node and is normally invoked automatically by the
kernel-update hook when a kernel package changes (e.g. 'apk upgrade linux-lts').
Without it, a kernel upgrade would leave an unsigned/stale UKI and the node would
fail to boot under enforced UEFI Secure Boot.

Pipeline (never-brick):
  1. Resolve the kernel version (default: newest under /lib/modules).
  2. Rebuild the UKI for that kernel with the persisted kernel cmdline (dracut).
  3. Resolve the Secure Boot DB signer the same way the installer does:
       - resign-mode local : read the file:// DB key from the encrypted root.
       - resign-mode remote: hash-sign via the platform SDK (key stays in the KMS).
     It NEVER generates a new DB key (that would brick Secure Boot).
  4. Sign + VERIFY the rebuilt UKI against the DB certificate, and spot-check the
     freshly installed kernel modules for signatures.
  5. ONLY THEN atomically swap it over /boot/efi/EFI/BOOT/BOOTX64.EFI, keeping
     the previous image as BOOTX64.EFI.prev.

On any failure the swap is aborted, the working UKI is left in place, and a
non-zero exit code is returned so the kernel hook logs it — the OLD kernel still
boots.

Examples:
  # Rebuild for a specific kernel version (as the kernel hook invokes it)
  platformctl install uki-rebuild --kver 6.6.67-0-lts

  # Rebuild for the newest installed kernel
  platformctl install uki-rebuild`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUKIRebuild(getFlags(), cmdFlags)
		},
	}

	cmd.Flags().StringVar(&cmdFlags.kver, "kver", "", "Kernel version to (re)build the UKI for (default: newest under /lib/modules)")
	cmd.Flags().StringVar(&cmdFlags.config, "config", "", "Path to platform config (default: /etc/platformd/config.yaml, then /etc/platformd/install.yaml)")
	cmd.Flags().StringVar(&cmdFlags.espUKIPath, "uki", "", "Live UKI path to replace (default: the host architecture's loader under /boot/efi/EFI/BOOT, e.g. BOOTX64.EFI or BOOTAA64.EFI)")
	cmd.Flags().BoolVarP(&cmdFlags.verbose, "verbose", "v", false, "Enable verbose logging")
	cmd.Flags().BoolVar(&cmdFlags.debug, "debug", false, "Enable debug logging (implies verbose)")

	return cmd
}

// runUKIRebuild loads the platform config, wires the DB signer for the
// configured resign-mode, and runs the never-brick rebuild.
func runUKIRebuild(flags *cli.CommonFlags, cmdFlags *ukiRebuildFlags) error {
	logger := getInstallLogger(cmdFlags.verbose, cmdFlags.debug)

	config, err := loadUKIRebuildConfig(logger, cmdFlags.config)
	if err != nil {
		return err
	}

	if config.SecureBoot == nil || !config.SecureBoot.Enabled {
		logger.Info("Secure Boot disabled in config; nothing to re-sign")
		return nil
	}

	opts := []installer.UKIRebuildOption{}
	if cmdFlags.espUKIPath != "" {
		opts = append(opts, installer.WithESPUKIPath(cmdFlags.espUKIPath))
	}

	// resign-mode remote (and no file:// DB key) -> wire the remote KMS
	// hash-signing seam over the platform SDK client. file:// DB keys are
	// resolved locally inside the rebuilder and need no SDK connection.
	if config.SecureBoot.ResignMode == installer.SecureBootResignModeRemote &&
		!isFileURI(config.SecureBoot.DB.KeyURI) {
		seam, closeFn, seamErr := newRemoteSignerSeam(flags, config.SecureBoot)
		if seamErr != nil {
			return seamErr
		}
		if closeFn != nil {
			defer func() { _ = closeFn() }()
		}
		opts = append(opts, installer.WithRemoteSigner(seam))
	}

	rebuilder := installer.NewUKIRebuilder(logger, config, opts...)
	if err := rebuilder.Rebuild(context.Background(), cmdFlags.kver); err != nil {
		logger.Error(err, "message", "UKI rebuild failed; existing UKI left in place")
		return err
	}

	logger.Info("UKI rebuilt, re-signed, verified, and atomically swapped")
	return nil
}

// ukiRebuildConfigFallbacks are the default config locations searched when no
// --config is given. It is a package var so tests can point it at a temp dir.
var ukiRebuildConfigFallbacks = []string{"/etc/platformd/config.yaml", "/etc/platformd/install.yaml"}

// loadUKIRebuildConfig loads the installer config from the first existing of:
// the --config path, then ukiRebuildConfigFallbacks.
func loadUKIRebuildConfig(logger *logging.Logger, configPath string) (*installer.Config, error) {
	for _, p := range append([]string{configPath}, ukiRebuildConfigFallbacks...) {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		config, err := loadUnifiedConfig(logger, p)
		if err != nil {
			return nil, ErrConfigLoadFailed{Path: p, Err: err}
		}
		logger.Info("Loaded configuration", "path", p)
		return config, nil
	}
	return nil, ErrUKIRebuildConfigNotFound{Path: configPath}
}

// newRemoteSignerSeam builds the post-install remote DB hash-signing seam from
// the platform SDK client (IDevID mTLS). The Secure Boot DB private key stays in
// the control-plane KMS: the seam round-trips only the digest through the
// platform KeyManagementService Sign RPC (cl.KMS().Sign) and fetches the
// companion DB certificate through the CA service (secureboot.NewKMSSigner).
// The returned closer releases the SDK connection.
func newRemoteSignerSeam(flags *cli.CommonFlags, sb *installer.SecureBootConfig) (installer.RemoteSignerResolver, func() error, error) {
	if secureboot.KMSKeyID(sb.DB.KeyURI) == "" {
		return nil, nil, ErrRemoteSignKeyRef{KeyURI: sb.DB.KeyURI}
	}
	bc, err := cli.NewBaseCommand(flags)
	if err != nil {
		return nil, nil, ErrRemoteSignerSetup{Err: err}
	}
	cl := bc.Client()

	seam := func(ctx context.Context, _ *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
		return secureboot.NewKMSSigner(ctx, cl.KMS(), cl.CA(), sb.DB.KeyURI, sb.DB.CertURI)
	}
	return seam, bc.Close, nil
}

// isFileURI reports whether uri is a file:// reference (case-insensitive).
func isFileURI(uri string) bool {
	return strings.HasPrefix(strings.ToLower(uri), "file://")
}
