package diskimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

const rpiEEPROMHSMAlgorithm = "rsa2048-sha256"

type rpiEEPROMHSMFlags struct {
	fleetKey  string
	fleetCert string
	algorithm string
}

func newRPIEEPROMHSMCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return newRPIEEPROMHSMCommandWithClients(getFlags, nil)
}

func newRPIEEPROMHSMCommandWithClients(getFlags func() *cli.CommonFlags, clients pkgiso.KMSClientsFunc) *cobra.Command {
	flags := &rpiEEPROMHSMFlags{algorithm: rpiEEPROMHSMAlgorithm}
	cmd := &cobra.Command{
		Use:   "rpi-eeprom-hsm <file>",
		Short: "Sign Raspberry Pi EEPROM digest inputs with the fleet KMS key",
		Long: `Sign one file using the Raspberry Pi bootloader HSM-wrapper contract.

rpi-eeprom-digest invokes the wrapper as:
  wrapper -a rsa2048-sha256 <file>

Use this command from a tiny wrapper script that supplies --fleet-key and then
forwards "$@"; the command prints the raw RSA-2048/SHA-256 signature as
lowercase hex on stdout.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			signClients := clients
			if signClients == nil {
				platformClient := cli.NewLazyClient(getFlags())
				defer func() {
					if closeErr := platformClient.Close(); closeErr != nil && err == nil {
						err = &ErrEEPROMHSMSign{Step: "closing the platform connection", Err: closeErr}
					}
				}()
				signClients = kmsClients(platformClient)
			}
			return runRPIEEPROMHSM(cmd.Context(), flags, args[0], signClients, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&flags.fleetKey, "fleet-key", "", "kms:// reference of the RSA-2048 fleet key")
	cmd.Flags().StringVar(&flags.fleetCert, "fleet-cert", "", "kms:// reference of the fleet key certificate (default: --fleet-key id); append #sha256=<fingerprint> to pin it")
	cmd.Flags().StringVarP(&flags.algorithm, "algorithm", "a", rpiEEPROMHSMAlgorithm, "wrapper algorithm from rpi-eeprom-digest")
	return cmd
}

func runRPIEEPROMHSM(ctx context.Context, flags *rpiEEPROMHSMFlags, file string, clients pkgiso.KMSClientsFunc, out io.Writer) error {
	if flags == nil {
		flags = &rpiEEPROMHSMFlags{}
	}
	if flags.algorithm != rpiEEPROMHSMAlgorithm {
		return &ErrEEPROMHSMAlgorithm{Algorithm: flags.algorithm}
	}
	if strings.TrimSpace(flags.fleetKey) == "" {
		return &ErrEEPROMHSMFlag{Flag: "fleet-key"}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return &ErrEEPROMHSMSign{Step: "reading " + file, Err: err}
	}
	kms, err := clients()
	if err != nil {
		return &ErrEEPROMHSMSign{Step: "connecting to the platform", Err: err}
	}
	signer, _, err := secureboot.NewKMSSigner(ctx, kms.KMS, kms.CA, flags.fleetKey, flags.fleetCert)
	if err != nil {
		return &ErrEEPROMHSMSign{Step: "opening the fleet key", Err: err}
	}
	sig, err := rpibootsig.SignDigest(signer, sha256.Sum256(data))
	if err != nil {
		return &ErrEEPROMHSMSign{Step: "signing " + file, Err: err}
	}
	if _, err := fmt.Fprintln(out, hex.EncodeToString(sig)); err != nil {
		return &ErrEEPROMHSMSign{Step: "writing the signature", Err: err}
	}
	return nil
}
