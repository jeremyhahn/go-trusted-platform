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

package tenant

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	sdktenant "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tenant"
)

// ---------------------------------------------------------------------------
// Per-Tenant Barrier CLI Commands (added 2026-04-28)
//
// Each tenant has an independent cryptographic barrier auto-initialized on
// CreateTenant and auto-sealed on DeleteTenant. These commands give explicit
// lifecycle control: init / unseal / seal / status.
//
// All commands use the platform SDK and route through the configured protocol
// (REST/gRPC/QUIC/MCP/Unix/embedded) per the user's --context selection.
// ---------------------------------------------------------------------------

// NewBarrierCommand creates the tenant barrier root command grouping the four
// barrier lifecycle subcommands.
func NewBarrierCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "barrier",
		Short: "Per-tenant cryptographic barrier lifecycle",
		Long: `Manage the per-tenant cryptographic barrier.

Each tenant has an independent barrier that is auto-initialized when the tenant
is created and auto-sealed when it is deleted. These subcommands provide
explicit lifecycle control:

  - init     Explicitly initialize a tenant barrier (idempotent if already
             initialized; required only when DEK isolation is enabled but
             auto-init was skipped). The barrier initializes with its
             deterministic credential; Shamir sharing is refused.
  - unseal   Unseal a sealed barrier with the supplied key bytes. Empty key
             falls back to the deterministic init credential.
  - seal     Seal a previously initialized barrier. Subsequent reads/writes
             against the tenant namespace fail until unsealed again.
  - status   Report sealed/initialized state and active strategy metadata.

Examples:
  # Initialize a tenant barrier (deterministic init)
  platformctl tenant barrier init my-tenant

  # Unseal a sealed tenant barrier with a hex-encoded key
  platformctl tenant barrier unseal my-tenant --key-hex deadbeef...

  # Seal a tenant barrier
  platformctl tenant barrier seal my-tenant

  # Inspect status as JSON
  platformctl tenant barrier status my-tenant -o json`,
	}

	cmd.AddCommand(newBarrierInitCommand(getFlags))
	cmd.AddCommand(newBarrierUnsealCommand(getFlags))
	cmd.AddCommand(newBarrierSealCommand(getFlags))
	cmd.AddCommand(newBarrierStatusCommand(getFlags))

	return cmd
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

func newBarrierInitCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var threshold, shares int32

	cmd := &cobra.Command{
		Use:   "init <tenant-name>",
		Short: "Initialize a per-tenant barrier",
		Long: `Initialize a per-tenant cryptographic barrier.

The barrier initializes with a deterministic credential derived from the
tenant ID, and the init returns no shares. Shamir sharing is not supported:
--threshold and --shares must stay 0 (the default), and the daemon refuses any
other value with InvalidArgument.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBarrierInit(getFlags(), args[0], threshold, shares)
		},
	}

	cmd.Flags().Int32Var(&threshold, "threshold", 0, "Shamir threshold; must be 0, any other value is refused")
	cmd.Flags().Int32Var(&shares, "shares", 0, "Shamir total shares; must be 0, any other value is refused")

	return cmd
}

func runBarrierInit(flags *cli.CommonFlags, tenantName string, threshold, shares int32) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())
	ctx := context.Background()

	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	if err := tenantClient.InitTenantBarrier(ctx, t.ID, threshold, shares); err != nil {
		return ErrOperationFailed{Operation: "barrier init", TenantID: t.ID, Err: err}
	}

	printer := base.Printer()

	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(&BarrierInitResponse{
			TenantID:   t.ID,
			TenantName: tenantName,
			Threshold:  threshold,
			Shares:     shares,
			Success:    true,
		})
	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant barrier initialized for %s", tenantName))
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// BarrierInitResponse is the JSON/YAML output of `tenant barrier init`.
type BarrierInitResponse struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	Threshold  int32  `json:"threshold" yaml:"threshold"`
	Shares     int32  `json:"shares" yaml:"shares"`
	Success    bool   `json:"success" yaml:"success"`
}

// ---------------------------------------------------------------------------
// unseal
// ---------------------------------------------------------------------------

func newBarrierUnsealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var keyHex, keyB64 string

	cmd := &cobra.Command{
		Use:   "unseal <tenant-name>",
		Short: "Unseal a per-tenant barrier",
		Long: `Unseal a per-tenant barrier with the supplied key material.

Provide the key in either hex (--key-hex) or base64 (--key-base64). When
both are empty the server falls back to its deterministic init credential
(used only when the barrier was initialized via deterministic init).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBarrierUnseal(getFlags(), args[0], keyHex, keyB64)
		},
	}

	cmd.Flags().StringVar(&keyHex, "key-hex", "", "Unseal key as hex-encoded bytes")
	cmd.Flags().StringVar(&keyB64, "key-base64", "", "Unseal key as base64-encoded bytes")

	return cmd
}

func runBarrierUnseal(flags *cli.CommonFlags, tenantName, keyHex, keyB64 string) error {
	if keyHex != "" && keyB64 != "" {
		return ErrInvalidArguments{Reason: "specify only one of --key-hex or --key-base64"}
	}

	var key []byte
	switch {
	case keyHex != "":
		decoded, err := hex.DecodeString(strings.TrimPrefix(keyHex, "0x"))
		if err != nil {
			return ErrInvalidArguments{Reason: fmt.Sprintf("invalid --key-hex: %v", err)}
		}
		key = decoded
	case keyB64 != "":
		decoded, err := base64.StdEncoding.DecodeString(keyB64)
		if err != nil {
			return ErrInvalidArguments{Reason: fmt.Sprintf("invalid --key-base64: %v", err)}
		}
		key = decoded
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())
	ctx := context.Background()

	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	if err := tenantClient.UnsealTenantBarrier(ctx, t.ID, key); err != nil {
		return ErrOperationFailed{Operation: "barrier unseal", TenantID: t.ID, Err: err}
	}

	printer := base.Printer()
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(&BarrierUnsealResponse{
			TenantID:   t.ID,
			TenantName: tenantName,
			Success:    true,
		})
	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant barrier unsealed for %s", tenantName))
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// BarrierUnsealResponse is the JSON/YAML output of `tenant barrier unseal`.
type BarrierUnsealResponse struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	Success    bool   `json:"success" yaml:"success"`
}

// ---------------------------------------------------------------------------
// seal
// ---------------------------------------------------------------------------

func newBarrierSealCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "seal <tenant-name>",
		Short: "Seal a per-tenant barrier",
		Long: `Seal a previously initialized per-tenant barrier. Subsequent reads
and writes against the tenant namespace fail until unsealed again.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBarrierSeal(getFlags(), args[0])
		},
	}
	return cmd
}

func runBarrierSeal(flags *cli.CommonFlags, tenantName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())
	ctx := context.Background()

	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	if err := tenantClient.SealTenantBarrier(ctx, t.ID); err != nil {
		return ErrOperationFailed{Operation: "barrier seal", TenantID: t.ID, Err: err}
	}

	printer := base.Printer()
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(&BarrierSealResponse{
			TenantID:   t.ID,
			TenantName: tenantName,
			Success:    true,
		})
	case cli.OutputFormatTable:
		printer.PrintSuccess(fmt.Sprintf("Tenant barrier sealed for %s", tenantName))
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// BarrierSealResponse is the JSON/YAML output of `tenant barrier seal`.
type BarrierSealResponse struct {
	TenantID   string `json:"tenant_id" yaml:"tenant_id"`
	TenantName string `json:"tenant_name" yaml:"tenant_name"`
	Success    bool   `json:"success" yaml:"success"`
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func newBarrierStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <tenant-name>",
		Short: "Report per-tenant barrier status",
		Long: `Report the current sealed/initialized state and active strategy
metadata for a per-tenant barrier. Uninitialized barriers report sealed=true
and initialized=false rather than erroring.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBarrierStatus(getFlags(), args[0])
		},
	}
	return cmd
}

func runBarrierStatus(flags *cli.CommonFlags, tenantName string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	tenantClient := sdktenant.NewClientFromGRPC(base.Client().Tenant())
	ctx := context.Background()

	t, err := tenantClient.GetByNameDomain(ctx, tenantName)
	if err != nil {
		return ErrTenantNotFound{Name: tenantName}
	}

	st, err := tenantClient.GetTenantBarrierStatus(ctx, t.ID)
	if err != nil {
		return ErrOperationFailed{Operation: "barrier status", TenantID: t.ID, Err: err}
	}

	resp := &BarrierStatusResponse{
		TenantID:       t.ID,
		TenantName:     tenantName,
		Sealed:         st.GetSealed(),
		Initialized:    st.GetInitialized(),
		Strategy:       st.GetStrategy(),
		HardwareBacked: st.GetHardwareBacked(),
	}

	printer := base.Printer()
	switch flags.OutputFormat {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)
	case cli.OutputFormatTable:
		printer.PrintInfo(fmt.Sprintf("Tenant:          %s (%s)", tenantName, t.ID))
		printer.PrintInfo(fmt.Sprintf("Sealed:          %t", resp.Sealed))
		printer.PrintInfo(fmt.Sprintf("Initialized:     %t", resp.Initialized))
		printer.PrintInfo(fmt.Sprintf("Strategy:        %s", resp.Strategy))
		printer.PrintInfo(fmt.Sprintf("Hardware Backed: %t", resp.HardwareBacked))
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(flags.OutputFormat)}
	}
}

// BarrierStatusResponse is the JSON/YAML output of `tenant barrier status`.
type BarrierStatusResponse struct {
	TenantID       string `json:"tenant_id" yaml:"tenant_id"`
	TenantName     string `json:"tenant_name" yaml:"tenant_name"`
	Sealed         bool   `json:"sealed" yaml:"sealed"`
	Initialized    bool   `json:"initialized" yaml:"initialized"`
	Strategy       string `json:"strategy" yaml:"strategy"`
	HardwareBacked bool   `json:"hardware_backed" yaml:"hardware_backed"`
}
