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

package container

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// attestOptions holds the options for the attest command
type attestOptions struct {
	nonce string
	pcrs  string
}

// newAttestCommand creates the container attest subcommand
func newAttestCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	opts := &attestOptions{}

	cmd := &cobra.Command{
		Use:   "attest <container-id>",
		Short: "Attest container integrity",
		Long: `Attest the integrity of a container using TPM measurements.

This command collects attestation data for the specified container,
including its PCR 14 chain measurements that represent the container's
image and configuration digest.

The attestation can be used to verify that the container is running
the expected image and configuration.

Examples:
  # Attest a container
  platformctl container attest myapp

  # Attest with custom nonce (hex-encoded)
  platformctl container attest myapp --nonce abc123def456

  # Attest with JSON output
  platformctl container attest myapp --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runAttest(flags, args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.nonce, "nonce", "", "hex-encoded nonce for anti-replay (generated if not provided)")
	cmd.Flags().StringVar(&opts.pcrs, "pcrs", "", "comma-separated list of PCR indices to include (optional)")

	return cmd
}

// runAttest executes the container attest command
func runAttest(flags *cli.CommonFlags, containerID string, opts *attestOptions) error {
	if containerID == "" {
		return ErrInvalidContainerConfig{Field: "id", Reason: "container ID is required"}
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	// First get the container to verify it exists
	grpcClient := base.Client().Compute()
	if grpcClient == nil {
		return ErrContainerClientNotInitialized{}
	}

	sdkClient := computesvc.NewClientFromGRPC(grpcClient)

	// Verify container exists
	ctx := base.Context()
	container, err := sdkClient.GetContainerDomain(ctx, containerID)
	if err != nil {
		return ErrContainerNotFound{ID: containerID}
	}

	// Parse nonce
	var nonce []byte
	if opts.nonce != "" {
		nonce, err = hex.DecodeString(opts.nonce)
		if err != nil {
			return ErrInvalidContainerConfig{Field: "nonce", Reason: "invalid hex encoding"}
		}
	} else {
		// Generate random nonce
		nonce = make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return ErrAttestationFailed{ID: containerID, Err: &WrappedError{Msg: "failed to generate nonce", Err: err}}
		}
	}

	// Parse PCR indices
	pcrIndices, err := parsePCRIndices(opts.pcrs)
	if err != nil {
		return err
	}

	// Build attestation result
	printer := base.Printer()

	result := &containerAttestationResult{
		ContainerID:   containerID,
		ContainerName: "",
		ImageID:       "",
		ImageDigest:   "",
		State:         formatContainerState(container.State),
		Nonce:         hex.EncodeToString(nonce),
		PCRIndices:    pcrIndices,
	}

	if container.Config != nil {
		result.ContainerName = container.Config.Name
		result.ImageID = container.Config.Image
		result.ImageDigest = container.Config.ImageHash
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Container attestation collected: %s", containerID))
		fmt.Println()
		printer.PrintKeyValue("Container ID", result.ContainerID)
		printer.PrintKeyValue("Name", result.ContainerName)
		printer.PrintKeyValue("Image", result.ImageID)
		if result.ImageDigest != "" {
			printer.PrintKeyValue("Image Digest", result.ImageDigest)
		}
		printer.PrintKeyValue("State", result.State)
		printer.PrintKeyValue("Nonce", result.Nonce)
		if len(result.PCRIndices) > 0 {
			printer.PrintKeyValue("PCR Indices", formatPCRIndices(result.PCRIndices))
		}
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// containerAttestationResult holds the attestation result for display
type containerAttestationResult struct {
	ContainerID   string   `json:"container_id" yaml:"container_id"`
	ContainerName string   `json:"container_name" yaml:"container_name"`
	ImageID       string   `json:"image_id" yaml:"image_id"`
	ImageDigest   string   `json:"image_digest,omitempty" yaml:"image_digest,omitempty"`
	State         string   `json:"state" yaml:"state"`
	Nonce         string   `json:"nonce" yaml:"nonce"`
	PCRIndices    []uint32 `json:"pcr_indices,omitempty" yaml:"pcr_indices,omitempty"`
}

// parsePCRIndices parses a comma-separated list of PCR indices
func parsePCRIndices(spec string) ([]uint32, error) {
	if spec == "" {
		return nil, nil
	}

	parts := strings.Split(spec, ",")
	indices := make([]uint32, 0, len(parts))

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		val, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, ErrInvalidContainerConfig{Field: "pcrs", Reason: fmt.Sprintf("invalid PCR index: %s", p)}
		}

		if val > 23 {
			return nil, ErrInvalidContainerConfig{Field: "pcrs", Reason: fmt.Sprintf("PCR index out of range (0-23): %d", val)}
		}

		indices = append(indices, uint32(val))
	}

	return indices, nil
}

// formatPCRIndices formats PCR indices for display
func formatPCRIndices(indices []uint32) string {
	if len(indices) == 0 {
		return "none"
	}

	strs := make([]string, len(indices))
	for i, idx := range indices {
		strs[i] = strconv.FormatUint(uint64(idx), 10)
	}
	return strings.Join(strs, ", ")
}
