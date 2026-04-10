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

package vtpm

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newQuoteCommand creates the quote subcommand for generating TPM quotes
func newQuoteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var (
		bundleID string
		nonce    string
		pcrs     string
	)

	cmd := &cobra.Command{
		Use:   "quote",
		Short: "Generate a TPM quote over specified PCRs",
		Long: `Generate a TPM quote over specified PCR (Platform Configuration Register)
values for attestation purposes.

A TPM quote is a signed statement from the TPM about the current values of
selected PCRs, bound to a nonce for freshness.

The nonce should be provided as a hex-encoded string.
PCR indices should be provided as a comma-separated list of integers.

Examples:
  # Generate a quote over PCRs 0, 1, and 7
  platformctl vtpm quote --bundle-id bundle-123 --nonce deadbeef --pcrs 0,1,7

  # Generate a quote and output as JSON
  platformctl vtpm quote --bundle-id bundle-123 --nonce abc123 --pcrs 0,1,7 -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runQuote(flags, bundleID, nonce, pcrs)
		},
	}

	cmd.Flags().StringVar(&bundleID, "bundle-id", "", "bundle ID (required)")
	cmd.Flags().StringVar(&nonce, "nonce", "", "hex-encoded nonce for freshness (required)")
	cmd.Flags().StringVar(&pcrs, "pcrs", "", "comma-separated list of PCR indices (required)")

	_ = cmd.MarkFlagRequired("bundle-id")
	_ = cmd.MarkFlagRequired("nonce")
	_ = cmd.MarkFlagRequired("pcrs")

	return cmd
}

// runQuote executes the quote command
func runQuote(flags *cli.CommonFlags, bundleID, nonce, pcrs string) error {
	if bundleID == "" {
		return ErrMissingRequiredFlag{Flag: "bundle-id"}
	}
	if nonce == "" {
		return ErrMissingRequiredFlag{Flag: "nonce"}
	}
	if pcrs == "" {
		return ErrMissingRequiredFlag{Flag: "pcrs"}
	}

	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return ErrInvalidNonce{Reason: err.Error()}
	}

	pcrIndices, err := parsePCRIndices(pcrs)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return ErrDaemonConnectionRequired{}
	}
	defer base.Close()

	client := base.Client().VTPM()
	if client == nil {
		return ErrVTPMNotAvailable{}
	}

	req := &platformv1.QuoteVTPMRequest{
		BundleId: bundleID,
		Nonce:    nonceBytes,
		Pcrs:     pcrIndices,
	}

	ctx := base.Context()
	resp, err := client.QuoteVTPM(ctx, req)
	if err != nil {
		return ErrQuoteVTPMFailed{Reason: err.Error()}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Bundle ID", resp.BundleId)
		printer.PrintKeyValue("Hash Algorithm", resp.HashAlgorithm)
		printer.PrintKeyValue("Quote", hex.EncodeToString(resp.Quote))
		printer.PrintKeyValue("Signature", hex.EncodeToString(resp.Signature))
		if len(resp.PcrValues) > 0 {
			fmt.Println()
			printer.PrintInfo("PCR Values:")
			for idx, val := range resp.PcrValues {
				printer.PrintKeyValue(fmt.Sprintf("  PCR[%d]", idx), hex.EncodeToString(val))
			}
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// parsePCRIndices parses a comma-separated list of PCR indices into int32 slice
func parsePCRIndices(pcrs string) ([]int32, error) {
	parts := strings.Split(pcrs, ",")
	indices := make([]int32, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		idx, err := strconv.ParseInt(trimmed, 10, 32)
		if err != nil {
			return nil, ErrInvalidPCRIndex{Index: trimmed, Reason: err.Error()}
		}
		if idx < 0 || idx > 23 {
			return nil, ErrInvalidPCRIndex{Index: trimmed, Reason: "PCR index must be between 0 and 23"}
		}
		indices = append(indices, int32(idx))
	}
	if len(indices) == 0 {
		return nil, ErrMissingRequiredFlag{Flag: "pcrs"}
	}
	return indices, nil
}
