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

package tpm

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// newNVRAMCommand creates the nvram command group for NVRAM operations
func newNVRAMCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "nvram",
		Short: "NVRAM operations",
		Long: `Perform operations on TPM 2.0 Non-Volatile RAM (NVRAM).

NVRAM provides persistent storage within the TPM that survives power cycles.
Common uses include storing certificates, policies, and configuration data.

Available subcommands:
  - define: Define a new NV index
  - write: Write data to an NV index
  - read: Read data from an NV index
  - delete: Delete (undefine) an NV index

Common NV Index Ranges:
  0x01000000-0x01FFFFFF  Owner-defined indices
  0x01400000-0x017FFFFF  Platform indices
  0x01800000-0x01BFFFFF  Endorsement indices
  0x01C00000-0x01FFFFFF  TCG-defined indices (EK certs, etc.)

Examples:
  # Define a new NV index with 256 bytes
  platformctl tpm nvram define --index 0x01000001 --size 256

  # Write data to an NV index
  platformctl tpm nvram write --index 0x01000001 --data "my secret data"

  # Read data from an NV index
  platformctl tpm nvram read --index 0x01000001

  # Delete an NV index
  platformctl tpm nvram delete --index 0x01000001`,
	}

	cmd.AddCommand(newNVRAMDefineCommand(getFlags))
	cmd.AddCommand(newNVRAMWriteCommand(getFlags))
	cmd.AddCommand(newNVRAMReadCommand(getFlags))
	cmd.AddCommand(newNVRAMDeleteCommand(getFlags))

	return cmd
}

// newNVRAMDefineCommand creates the define subcommand for NVRAM
func newNVRAMDefineCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var index uint32
	var size uint32
	var password string
	var attributes []string

	cmd := &cobra.Command{
		Use:   "define",
		Short: "Define a new NV index",
		Long: `Define a new NV index in the TPM.

The NV index will be created with the specified size and attributes.

Examples:
  # Define NV index with 256 bytes
  platformctl tpm nvram define --index 0x01000001 --size 256

  # Define with password protection
  platformctl tpm nvram define --index 0x01000001 --size 256 --password mypassword`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &nvramDefineOptions{
				Index:      index,
				Size:       size,
				Password:   password,
				Attributes: attributes,
			}
			return runNVRAMDefine(flags, opts)
		},
	}

	cmd.Flags().Uint32Var(&index, "index", 0, "NV index (e.g., 0x01000001)")
	cmd.Flags().Uint32Var(&size, "size", 0, "size of NV space in bytes")
	cmd.Flags().StringVar(&password, "password", "", "authorization password")
	cmd.Flags().StringSliceVar(&attributes, "attributes", nil, "NV attributes (AUTHWRITE, AUTHREAD, etc.)")

	_ = cmd.MarkFlagRequired("index")
	_ = cmd.MarkFlagRequired("size")

	return cmd
}

// nvramDefineOptions holds options for the NVRAM define command
type nvramDefineOptions struct {
	Index      uint32
	Size       uint32
	Password   string
	Attributes []string
}

// newNVRAMWriteCommand creates the write subcommand for NVRAM
func newNVRAMWriteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var index uint32
	var data string
	var password string
	var offset uint32

	cmd := &cobra.Command{
		Use:   "write",
		Short: "Write data to an NV index",
		Long: `Write data to an existing NV index in the TPM.

Examples:
  # Write string data
  platformctl tpm nvram write --index 0x01000001 --data "my secret data"

  # Write with password
  platformctl tpm nvram write --index 0x01000001 --data "data" --password mypassword

  # Write at offset
  platformctl tpm nvram write --index 0x01000001 --data "data" --offset 10`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &nvramWriteOptions{
				Index:    index,
				Data:     data,
				Password: password,
				Offset:   offset,
			}
			return runNVRAMWrite(flags, opts)
		},
	}

	cmd.Flags().Uint32Var(&index, "index", 0, "NV index")
	cmd.Flags().StringVar(&data, "data", "", "data to write")
	cmd.Flags().StringVar(&password, "password", "", "authorization password")
	cmd.Flags().Uint32Var(&offset, "offset", 0, "offset to write at")

	_ = cmd.MarkFlagRequired("index")
	_ = cmd.MarkFlagRequired("data")

	return cmd
}

// nvramWriteOptions holds options for the NVRAM write command
type nvramWriteOptions struct {
	Index    uint32
	Data     string
	Password string
	Offset   uint32
}

// newNVRAMReadCommand creates the read subcommand for NVRAM
func newNVRAMReadCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var index uint32
	var password string
	var offset uint32
	var size uint32
	var hexOutput bool

	cmd := &cobra.Command{
		Use:   "read",
		Short: "Read data from an NV index",
		Long: `Read data from an NV index in the TPM.

Examples:
  # Read all data from index
  platformctl tpm nvram read --index 0x01000001

  # Read with password
  platformctl tpm nvram read --index 0x01000001 --password mypassword

  # Read partial data
  platformctl tpm nvram read --index 0x01000001 --offset 10 --size 50

  # Read as hex
  platformctl tpm nvram read --index 0x01000001 --hex`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			opts := &nvramReadOptions{
				Index:     index,
				Password:  password,
				Offset:    offset,
				Size:      size,
				HexOutput: hexOutput,
			}
			return runNVRAMRead(flags, opts)
		},
	}

	cmd.Flags().Uint32Var(&index, "index", 0, "NV index")
	cmd.Flags().StringVar(&password, "password", "", "authorization password")
	cmd.Flags().Uint32Var(&offset, "offset", 0, "offset to read from")
	cmd.Flags().Uint32Var(&size, "size", 0, "number of bytes to read (0 for all)")
	cmd.Flags().BoolVar(&hexOutput, "hex", false, "output data as hexadecimal")

	_ = cmd.MarkFlagRequired("index")

	return cmd
}

// nvramReadOptions holds options for the NVRAM read command
type nvramReadOptions struct {
	Index     uint32
	Password  string
	Offset    uint32
	Size      uint32
	HexOutput bool
}

// newNVRAMDeleteCommand creates the delete subcommand for NVRAM
func newNVRAMDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var index uint32
	var password string

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete (undefine) an NV index",
		Long: `Delete (undefine) an NV index from the TPM.

WARNING: This operation is irreversible.

Examples:
  # Delete NV index
  platformctl tpm nvram delete --index 0x01000001

  # Delete with password
  platformctl tpm nvram delete --index 0x01000001 --password mypassword`,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags := getFlags()
			return runNVRAMDelete(flags, index, password)
		},
	}

	cmd.Flags().Uint32Var(&index, "index", 0, "NV index to delete")
	cmd.Flags().StringVar(&password, "password", "", "authorization password")

	_ = cmd.MarkFlagRequired("index")

	return cmd
}

// runNVRAMDefine executes the NVRAM define command
func runNVRAMDefine(flags *cli.CommonFlags, opts *nvramDefineOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runNVRAMDefineWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runNVRAMDefineWithClient runs NVRAM define with a testable interface
func runNVRAMDefineWithClient(base TPMBaseCommandInterface, opts *nvramDefineOptions) error {
	defer base.Close()

	req := &platformv1.DefineNVRAMRequest{
		Index:      opts.Index,
		Size:       opts.Size,
		Password:   opts.Password,
		Attributes: opts.Attributes,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().DefineNVRAM(ctx, req)
	if err != nil {
		return ErrNVRAMDefineFailed{Index: opts.Index, Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrNVRAMDefineFailed{Index: opts.Index, Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success": resp.Status.Success,
		"index":   fmt.Sprintf("0x%08X", opts.Index),
		"size":    opts.Size,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("NV index 0x%08X defined with %d bytes", opts.Index, opts.Size))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runNVRAMWrite executes the NVRAM write command
func runNVRAMWrite(flags *cli.CommonFlags, opts *nvramWriteOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runNVRAMWriteWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runNVRAMWriteWithClient runs NVRAM write with a testable interface
func runNVRAMWriteWithClient(base TPMBaseCommandInterface, opts *nvramWriteOptions) error {
	defer base.Close()

	req := &platformv1.WriteNVRAMRequest{
		Index:    opts.Index,
		Data:     []byte(opts.Data),
		Password: opts.Password,
		Offset:   opts.Offset,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().WriteNVRAM(ctx, req)
	if err != nil {
		return ErrNVRAMWriteFailed{Index: opts.Index, Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrNVRAMWriteFailed{Index: opts.Index, Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success": resp.Status.Success,
		"index":   fmt.Sprintf("0x%08X", opts.Index),
		"bytes":   len(opts.Data),
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Written %d bytes to NV index 0x%08X", len(opts.Data), opts.Index))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runNVRAMRead executes the NVRAM read command
func runNVRAMRead(flags *cli.CommonFlags, opts *nvramReadOptions) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runNVRAMReadWithClient(&tpmBaseCommandAdapter{base: base}, opts)
}

// runNVRAMReadWithClient runs NVRAM read with a testable interface
func runNVRAMReadWithClient(base TPMBaseCommandInterface, opts *nvramReadOptions) error {
	defer base.Close()

	req := &platformv1.ReadNVRAMRequest{
		Index:    opts.Index,
		Password: opts.Password,
		Offset:   opts.Offset,
		Size:     opts.Size,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().ReadNVRAM(ctx, req)
	if err != nil {
		return ErrNVRAMReadFailed{Index: opts.Index, Reason: err.Error()}
	}

	printer := base.Printer()
	flags := base.Flags()

	var dataStr string
	if opts.HexOutput {
		dataStr = hex.EncodeToString(resp.Data)
	} else {
		dataStr = string(resp.Data)
	}

	output := map[string]interface{}{
		"index": fmt.Sprintf("0x%08X", opts.Index),
		"size":  len(resp.Data),
		"data":  dataStr,
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintKeyValue("Index", fmt.Sprintf("0x%08X", opts.Index))
		printer.PrintKeyValue("Size", fmt.Sprintf("%d bytes", len(resp.Data)))
		fmt.Println()
		fmt.Println(dataStr)
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// runNVRAMDelete executes the NVRAM delete command
func runNVRAMDelete(flags *cli.CommonFlags, index uint32, password string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	return runNVRAMDeleteWithClient(&tpmBaseCommandAdapter{base: base}, index, password)
}

// runNVRAMDeleteWithClient runs NVRAM delete with a testable interface
func runNVRAMDeleteWithClient(base TPMBaseCommandInterface, index uint32, password string) error {
	defer base.Close()

	req := &platformv1.UndefineNVRAMRequest{
		Index:    index,
		Password: password,
	}

	ctx := base.Context()
	resp, err := base.TPMClient().UndefineNVRAM(ctx, req)
	if err != nil {
		return ErrNVRAMDeleteFailed{Index: index, Reason: err.Error()}
	}

	if resp.Status == nil || !resp.Status.Success {
		msg := "unknown error"
		if resp.Status != nil && resp.Status.Message != "" {
			msg = resp.Status.Message
		}
		return ErrNVRAMDeleteFailed{Index: index, Reason: msg}
	}

	printer := base.Printer()
	flags := base.Flags()

	output := map[string]interface{}{
		"success": resp.Status.Success,
		"index":   fmt.Sprintf("0x%08X", index),
	}

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(output)

	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("NV index 0x%08X deleted", index))
		return nil

	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}
