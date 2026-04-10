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

package provision

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// defaultTimeoutSeconds is the default interactive provisioning timeout.
const defaultTimeoutSeconds = 600

// pollIntervalSeconds is the interval between poll requests.
const pollIntervalSeconds = 5

// newInteractiveCommand creates the interactive subcommand for QR-based
// interactive provisioning.
func newInteractiveCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags provisionFlags

	cmd := &cobra.Command{
		Use:   "interactive",
		Short: "Interactive QR provisioning",
		Long: `Start interactive provisioning by displaying a QR code on the console.

This command is used when fetch-config returns exit code 2 (pending).
It displays a QR code that an operator scans to approve the device,
then polls the server until the config is available or timeout expires.

The QR code encodes a URL that the operator opens in a browser to
approve the device provisioning.

Examples:
  # Interactive provisioning with default 10-minute timeout
  platformctl provision interactive \
    --server-url https://platform:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid key-id \
    --eab-hmac base64-hmac \
    --output /tmp/platform-config.yaml

  # With custom timeout
  platformctl provision interactive \
    --server-url https://platform:8443 \
    --ek-serial ABC123 \
    --mac 00:11:22:33:44:55 \
    --eab-kid key-id \
    --eab-hmac base64-hmac \
    --output /tmp/platform-config.yaml \
    --timeout 300`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractive(&flags)
		},
	}

	cmd.Flags().StringVar(&flags.serverURL, "server-url", "", "provisioning server URL (required)")
	cmd.Flags().StringVar(&flags.ekSerial, "ek-serial", "", "device EK serial number (required)")
	cmd.Flags().StringVar(&flags.mac, "mac", "", "device MAC address (required)")
	cmd.Flags().StringVar(&flags.eabKID, "eab-kid", "", "EAB key ID (required)")
	cmd.Flags().StringVar(&flags.eabHMAC, "eab-hmac", "", "EAB HMAC (required)")
	cmd.Flags().StringVar(&flags.output, "output", "", "output path for config YAML (required)")
	cmd.Flags().IntVar(&flags.timeout, "timeout", defaultTimeoutSeconds, "timeout in seconds")

	return cmd
}

// runInteractive executes the interactive provisioning command. It fetches a
// nonce, sends the config request, displays the provisioning URL, and polls
// the server until the device is approved or timeout expires.
func runInteractive(flags *provisionFlags) error {
	if err := validateProvisionFlags(flags); err != nil {
		return err
	}
	if flags.timeout <= 0 {
		return ErrInvalidTimeout{Value: flags.timeout}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flags.timeout)*time.Second)
	defer cancel()

	client := &http.Client{}

	// Fetch nonce from the server
	nonce, err := fetchNonce(ctx, client, flags.serverURL)
	if err != nil {
		return err
	}

	// Build and send config request
	cfgReq := buildConfigRequest(flags, nonce)
	cfgResp, err := sendConfigRequest(ctx, client, flags.serverURL, cfgReq)
	if err != nil {
		return err
	}

	// If config is already available, write it and return
	if cfgResp.Status == statusOK {
		if err := writeConfigToFile(cfgResp.Config, flags.output); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Config written to %s\n", flags.output)
		return nil
	}

	// Status must be pending with a provision URL
	if cfgResp.Status != statusPending {
		return ErrUnexpectedStatus{
			StatusCode: http.StatusOK,
			Body:       "unexpected status: " + cfgResp.Status,
		}
	}

	// Display provisioning information on console
	qrText := generateQRText(cfgResp.ProvisionURL)
	fmt.Fprint(os.Stdout, qrText)
	fmt.Fprintf(os.Stdout, "\nDevice Info:\n")
	fmt.Fprintf(os.Stdout, "  EK Serial: %s\n", flags.ekSerial)
	fmt.Fprintf(os.Stdout, "  MAC:       %s\n", flags.mac)
	fmt.Fprintf(os.Stdout, "\nScan QR code to provision this device\n")
	fmt.Fprintf(os.Stdout, "Waiting for approval (timeout: %ds)...\n\n", flags.timeout)

	// Poll for fulfillment using a ticker and select
	return pollForConfig(ctx, client, flags.serverURL, cfgResp.SessionID, flags.output, flags.timeout)
}

// pollForConfig polls the provisioning server at regular intervals until the
// config becomes available, the context is cancelled, or timeout expires.
func pollForConfig(ctx context.Context, client *http.Client, serverURL, sessionID, outputPath string, timeout int) error {
	ticker := time.NewTicker(pollIntervalSeconds * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ErrPollTimeout{SessionID: sessionID, Timeout: timeout}

		case <-ticker.C:
			pollResp, err := pollSession(ctx, client, serverURL, sessionID)
			if err != nil {
				// Log the error but keep polling; transient failures
				// should not abort the provisioning flow.
				fmt.Fprintf(os.Stderr, "Poll error (retrying): %v\n", err)
				continue
			}

			if pollResp.Status == statusOK {
				if err := writeConfigToFile(pollResp.Config, outputPath); err != nil {
					return err
				}
				fmt.Fprintf(os.Stdout, "\nDevice approved. Config written to %s\n", outputPath)
				return nil
			}
		}
	}
}
