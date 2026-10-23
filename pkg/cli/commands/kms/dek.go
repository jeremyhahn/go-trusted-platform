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

package kms

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	kmspb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dekclient "github.com/jeremyhahn/go-quicbaas/sdk/go/client/dek"
	sdkkms "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

// dekCreateAlgorithm is the AEAD every `kms dek create` DEK uses. It is the
// algorithm the gRPC, QUIC and MCP transports send when the caller leaves the
// algorithm unset, so a DEK created from the CLI matches one created there.
var dekCreateAlgorithm = sdkkms.AlgorithmAES256GCM.String()

// ErrDEKOperationFailed wraps an SDK DEK client failure with the verb and path.
type ErrDEKOperationFailed struct {
	Verb string
	Path string
	Err  error
}

func (e ErrDEKOperationFailed) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("dek %s failed: %v", e.Verb, e.Err)
	}
	return fmt.Sprintf("dek %s %s failed: %v", e.Verb, e.Path, e.Err)
}

func (e ErrDEKOperationFailed) Unwrap() error {
	return e.Err
}

// ErrDEKSDKGap is returned when a documented option has no counterpart in the
// go-quicbaas SDK DEK client. It names what the SDK lacks; the CLI never
// reaches past the SDK to fill the gap.
type ErrDEKSDKGap struct {
	Option  string
	Missing string
}

func (e ErrDEKSDKGap) Error() string {
	return fmt.Sprintf("dek %s: the go-quicbaas SDK DEK client has no %s", e.Option, e.Missing)
}

// ErrDEKServiceUnavailable is returned when the SDK exposes no DEK client.
type ErrDEKServiceUnavailable struct{}

func (e ErrDEKServiceUnavailable) Error() string {
	return "the DEK service is not available on this connection"
}

// ErrDEKClearSafetyNotConfirmed is returned when clear-safety runs without
// --force: removing a DEK's AEAD limits is never done implicitly.
type ErrDEKClearSafetyNotConfirmed struct {
	Path string
}

func (e ErrDEKClearSafetyNotConfirmed) Error() string {
	return fmt.Sprintf("dek clear-safety %s removes the DEK's AEAD safety limits; pass --force to confirm", e.Path)
}

// ErrInvalidDEKLimit is returned when `dek list --limit` is not positive.
type ErrInvalidDEKLimit struct {
	Limit int32
}

func (e ErrInvalidDEKLimit) Error() string {
	return fmt.Sprintf("invalid --limit %d: must be greater than zero", e.Limit)
}

// dekClientFactory builds the SDK DEK client a `kms dek` verb calls.
type dekClientFactory func(base *cli.BaseCommand) (dekclient.Client, error)

// activeDEKClientFactory is the seam unit tests replace with a fake client.
var activeDEKClientFactory dekClientFactory = defaultDEKClientFactory

func defaultDEKClientFactory(base *cli.BaseCommand) (dekclient.Client, error) {
	q, err := base.Client().QuicBaaS()
	if err != nil {
		return nil, err
	}
	client := q.Security().DEK()
	if client == nil {
		return nil, ErrDEKServiceUnavailable{}
	}
	return client, nil
}

// setDEKClientFactory replaces the DEK client factory and returns a restore func.
func setDEKClientFactory(f dekClientFactory) func() {
	prev := activeDEKClientFactory
	activeDEKClientFactory = f
	return func() { activeDEKClientFactory = prev }
}

// ErrDEKStatusEmpty is returned when the DEKManagement service answers a
// status request without the DEK's metadata.
type ErrDEKStatusEmpty struct {
	Path string
}

func (e ErrDEKStatusEmpty) Error() string {
	return fmt.Sprintf("dek status %s: the DEK service returned no DEK metadata", e.Path)
}

// dekStatusClient is the quicbaas.kms.v1 DEKManagement status call platformd
// registers beside its own services (DEKServerAdapter in pkg/api/daemon).
type dekStatusClient interface {
	GetDEKStatus(ctx context.Context, in *kmspb.GetDEKStatusRequest, opts ...grpc.CallOption) (*kmspb.GetDEKStatusResponse, error)
}

// dekStatusSource fetches one DEK's status in the shape `kms dek status` prints.
type dekStatusSource func(ctx context.Context, path string) (dekStatusOutput, error)

// dekStatusSourceFactory builds the source `kms dek status` reads.
type dekStatusSourceFactory func(base *cli.BaseCommand) (dekStatusSource, error)

// activeDEKStatusSourceFactory is the seam unit tests replace with a fake source.
var activeDEKStatusSourceFactory dekStatusSourceFactory = defaultDEKStatusSourceFactory

// platformDEKStatusProtocols are the platform transports that carry
// DEKManagement: gRPC and Unix through platformd's registration, QUIC through
// the sdk/go/transport/quic DEK mapping.
var platformDEKStatusProtocols = map[platform.Protocol]bool{
	platform.ProtocolGRPC: true,
	platform.ProtocolUnix: true,
	platform.ProtocolQUIC: true,
}

// defaultDEKStatusSourceFactory reads status from platformd's DEKManagement
// service where the platform transport carries it: the pinned SDK DEK client
// cannot send GetDEKStatus over its gRPC and Unix transports. Every other
// platform transport keeps the SDK DEK client.
func defaultDEKStatusSourceFactory(base *cli.BaseCommand) (dekStatusSource, error) {
	return dekStatusSourceFor(base.Client(), func() (dekclient.Client, error) {
		return activeDEKClientFactory(base)
	})
}

// dekStatusSourceFor picks the status source for client's platform transport;
// sdkClient opens the SDK DEK client for the transports that keep it.
func dekStatusSourceFor(client platform.Client, sdkClient func() (dekclient.Client, error)) (dekStatusSource, error) {
	if platformDEKStatusProtocols[client.Protocol()] {
		dek := client.DEK()
		if dek == nil {
			return nil, ErrDEKServiceUnavailable{}
		}
		return platformDEKStatus(dek), nil
	}
	sdk, err := sdkClient()
	if err != nil {
		return nil, err
	}
	return sdkDEKStatus(sdk), nil
}

// setDEKStatusSourceFactory replaces the status source factory and returns a restore func.
func setDEKStatusSourceFactory(f dekStatusSourceFactory) func() {
	prev := activeDEKStatusSourceFactory
	activeDEKStatusSourceFactory = f
	return func() { activeDEKStatusSourceFactory = prev }
}

// platformDEKStatus reads status from platformd's DEKManagement service.
func platformDEKStatus(client dekStatusClient) dekStatusSource {
	return func(ctx context.Context, path string) (dekStatusOutput, error) {
		resp, err := client.GetDEKStatus(ctx, &kmspb.GetDEKStatusRequest{Path: path})
		if err != nil {
			return dekStatusOutput{}, err
		}
		if resp.GetDek() == nil {
			return dekStatusOutput{}, ErrDEKStatusEmpty{Path: path}
		}
		out := dekStatusOutput{dekOutput: newDEKOutputFromPb(resp.GetDek())}
		if p := resp.GetReencryptionProgress(); p != nil {
			out.Reencryption = &dekReencryptionOutput{
				InProgress:      p.GetInProgress(),
				TotalKeys:       int(p.GetTotalKeys()),
				ProcessedKeys:   int(p.GetProcessedKeys()),
				FailedKeys:      int(p.GetFailedKeys()),
				PercentComplete: reencryptionPercent(p.GetProcessedKeys(), p.GetTotalKeys()),
				StartedAt:       formatUnixOrEmpty(p.GetStartedAt()),
			}
		}
		return out, nil
	}
}

// sdkDEKStatus reads status through the go-quicbaas SDK DEK client.
func sdkDEKStatus(client dekclient.Client) dekStatusSource {
	return func(ctx context.Context, path string) (dekStatusOutput, error) {
		resp, err := client.GetDEKStatus(ctx, path)
		if err != nil {
			return dekStatusOutput{}, err
		}
		if resp.DEK == nil {
			return dekStatusOutput{}, ErrDEKStatusEmpty{Path: path}
		}
		out := dekStatusOutput{dekOutput: newDEKOutput(resp.DEK)}
		if p := resp.ReencryptionProgress; p != nil {
			out.Reencryption = &dekReencryptionOutput{
				InProgress:      p.InProgress,
				TotalKeys:       p.TotalKeys,
				ProcessedKeys:   p.ProcessedKeys,
				FailedKeys:      p.FailedKeys,
				PercentComplete: p.PercentComplete,
				StartedAt:       formatTimeOrEmpty(p.StartedAt),
				ErrorMessage:    p.ErrorMessage,
			}
		}
		return out, nil
	}
}

// ErrInvalidDEKWarnPercent is returned when --warn-percent is not a percentage.
type ErrInvalidDEKWarnPercent struct {
	Percent int
}

func (e ErrInvalidDEKWarnPercent) Error() string {
	return fmt.Sprintf("invalid --warn-percent %d: must be between 0 and 100", e.Percent)
}

// dekSafetyClient is the default and safety-limit calls `kms dek set-default`,
// `set-safety` and `clear-safety` make. dekclient.Client carries them, and so
// does platformDEKSafety over platformd's DEKManagement service.
type dekSafetyClient interface {
	SetDefaultDEK(ctx context.Context, path string) (*dekclient.SetDefaultDEKResponse, error)
	SetDEKSafety(ctx context.Context, req *dekclient.SetDEKSafetyRequest) error
	ClearDEKSafety(ctx context.Context, path string) error
}

// dekSafetyClientFactory builds the client the default and safety commands use.
type dekSafetyClientFactory func(base *cli.BaseCommand) (dekSafetyClient, error)

// activeDEKSafetyClientFactory is the seam unit tests replace with a fake client.
var activeDEKSafetyClientFactory dekSafetyClientFactory = defaultDEKSafetyClientFactory

// platformDEKSafetyProtocols are the platform transports on which the default
// and safety commands use platformd's DEKManagement service: the pinned SDK DEK
// client cannot send SetDefaultDEK, SetDEKSafety or ClearDEKSafety over its
// gRPC and Unix transports. QUIC keeps the SDK client, which carries them.
var platformDEKSafetyProtocols = map[platform.Protocol]bool{
	platform.ProtocolGRPC: true,
	platform.ProtocolUnix: true,
}

func defaultDEKSafetyClientFactory(base *cli.BaseCommand) (dekSafetyClient, error) {
	return dekSafetyClientFor(base.Client(), func() (dekclient.Client, error) {
		return activeDEKClientFactory(base)
	})
}

// dekSafetyClientFor picks the default and safety client for client's platform
// transport; sdkClient opens the SDK DEK client for the transports that keep it.
func dekSafetyClientFor(client platform.Client, sdkClient func() (dekclient.Client, error)) (dekSafetyClient, error) {
	if platformDEKSafetyProtocols[client.Protocol()] {
		dek := client.DEK()
		if dek == nil {
			return nil, ErrDEKServiceUnavailable{}
		}
		return platformDEKSafety{client: dek}, nil
	}
	sdk, err := sdkClient()
	if err != nil {
		return nil, err
	}
	return sdk, nil
}

// setDEKSafetyClientFactory replaces the default and safety client factory and
// returns a restore func.
func setDEKSafetyClientFactory(f dekSafetyClientFactory) func() {
	prev := activeDEKSafetyClientFactory
	activeDEKSafetyClientFactory = f
	return func() { activeDEKSafetyClientFactory = prev }
}

// platformDEKSafety makes the default and safety calls on platformd's
// DEKManagement service (DEKServerAdapter in pkg/api/daemon).
type platformDEKSafety struct {
	client kmspb.DEKManagementClient
}

func (p platformDEKSafety) SetDefaultDEK(ctx context.Context, path string) (*dekclient.SetDefaultDEKResponse, error) {
	resp, err := p.client.SetDefaultDEK(ctx, &kmspb.SetDefaultDEKRequest{Path: path})
	if err != nil {
		return nil, err
	}
	return &dekclient.SetDefaultDEKResponse{Path: resp.GetPath(), PreviousDefault: resp.GetPreviousDefault()}, nil
}

func (p platformDEKSafety) SetDEKSafety(ctx context.Context, req *dekclient.SetDEKSafetyRequest) error {
	if req.WarningPercent < 0 || req.WarningPercent > 100 {
		return ErrInvalidDEKWarnPercent{Percent: req.WarningPercent}
	}
	_, err := p.client.SetDEKSafety(ctx, &kmspb.SetDEKSafetyRequest{
		Path:           req.Path,
		MaxOperations:  req.MaxOperations,
		MaxBytes:       req.MaxBytes,
		WarningPercent: int32(req.WarningPercent),
	})
	return err
}

func (p platformDEKSafety) ClearDEKSafety(ctx context.Context, path string) error {
	_, err := p.client.ClearDEKSafety(ctx, &kmspb.ClearDEKSafetyRequest{Path: path})
	return err
}

// dekOutput is the JSON shape of one DEK. Times are RFC 3339, empty when unset.
type dekOutput struct {
	Path           string `json:"path"`
	Algorithm      string `json:"algorithm"`
	Version        int    `json:"version"`
	Status         string `json:"status"`
	IsDefault      bool   `json:"is_default"`
	CreatedAt      string `json:"created_at,omitempty"`
	RotatedAt      string `json:"rotated_at,omitempty"`
	UsageCount     uint64 `json:"usage_count"`
	BytesUsed      uint64 `json:"bytes_used"`
	MaxUsageCount  uint64 `json:"max_usage_count"`
	MaxBytesUsed   uint64 `json:"max_bytes_used"`
	WarningPercent int    `json:"warning_percent"`
	Description    string `json:"description,omitempty"`
	BackendType    string `json:"backend_type,omitempty"`
}

func newDEKOutput(info *dekclient.DEKInfo) dekOutput {
	if info == nil {
		return dekOutput{}
	}
	return dekOutput{
		Path:           info.Path,
		Algorithm:      info.Algorithm,
		Version:        info.Version,
		Status:         info.Status,
		IsDefault:      info.IsDefault,
		CreatedAt:      formatTimeOrEmpty(info.CreatedAt),
		RotatedAt:      formatTimeOrEmpty(info.RotatedAt),
		UsageCount:     info.UsageCount,
		BytesUsed:      info.BytesUsed,
		MaxUsageCount:  info.MaxUsageCount,
		MaxBytesUsed:   info.MaxBytesUsed,
		WarningPercent: info.WarningPercent,
		Description:    info.Description,
		BackendType:    info.BackendType,
	}
}

// dekAlgorithmNames maps the DEKManagement algorithm enum to the SDK names
// the other `kms dek` verbs print.
var dekAlgorithmNames = map[kmspb.KeyAlgorithm]string{
	kmspb.KeyAlgorithm_KEY_ALG_AES_256_GCM:       sdkkms.AlgorithmAES256GCM.String(),
	kmspb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305: sdkkms.AlgorithmChaCha20Poly1305.String(),
}

// dekAlgorithmName names alg as the SDK does; an algorithm the SDK has no
// DEK name for prints as its enum name rather than being dropped.
func dekAlgorithmName(alg kmspb.KeyAlgorithm) string {
	if name, ok := dekAlgorithmNames[alg]; ok {
		return name
	}
	return alg.String()
}

// formatUnixOrEmpty formats a Unix timestamp as RFC 3339, empty when unset.
func formatUnixOrEmpty(ts int64) string {
	if ts == 0 {
		return ""
	}
	return formatTimeOrEmpty(time.Unix(ts, 0))
}

func newDEKOutputFromPb(meta *kmspb.DEKMetadata) dekOutput {
	if meta == nil {
		return dekOutput{}
	}
	return dekOutput{
		Path:           meta.GetPath(),
		Algorithm:      dekAlgorithmName(meta.GetAlgorithm()),
		Version:        int(meta.GetVersion()),
		Status:         meta.GetStatus(),
		IsDefault:      meta.GetIsDefault(),
		CreatedAt:      formatUnixOrEmpty(meta.GetCreatedAt()),
		RotatedAt:      formatUnixOrEmpty(meta.GetRotatedAt()),
		UsageCount:     meta.GetUsageCount(),
		BytesUsed:      meta.GetBytesUsed(),
		MaxUsageCount:  meta.GetMaxUsageCount(),
		MaxBytesUsed:   meta.GetMaxBytesUsed(),
		WarningPercent: int(meta.GetWarningPercent()),
		Description:    meta.GetDescription(),
		BackendType:    meta.GetBackendType(),
	}
}

// reencryptionPercent is processed/total as a percentage, zero with no keys.
func reencryptionPercent(processed, total int32) float64 {
	if total <= 0 {
		return 0
	}
	return float64(processed) * 100 / float64(total)
}

type dekListOutput struct {
	DEKs       []dekOutput `json:"deks"`
	TotalCount int         `json:"total_count"`
}

type dekDeleteOutput struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
}

type dekRotateOutput struct {
	Path       string `json:"path"`
	OldVersion int    `json:"old_version"`
	NewVersion int    `json:"new_version"`
}

type dekReencryptionOutput struct {
	InProgress      bool    `json:"in_progress"`
	TotalKeys       int     `json:"total_keys"`
	ProcessedKeys   int     `json:"processed_keys"`
	FailedKeys      int     `json:"failed_keys"`
	PercentComplete float64 `json:"percent_complete"`
	StartedAt       string  `json:"started_at,omitempty"`
	ErrorMessage    string  `json:"error_message,omitempty"`
}

// dekStatusOutput is the DEK's fields plus its re-encryption progress, if any.
type dekStatusOutput struct {
	dekOutput
	Reencryption *dekReencryptionOutput `json:"reencryption,omitempty"`
}

type dekSetDefaultOutput struct {
	Path            string `json:"path"`
	PreviousDefault string `json:"previous_default,omitempty"`
}

// NewDEKCommand creates the DEK management command
func NewDEKCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dek",
		Short: "Data Encryption Key operations",
		Long: `Create, retrieve, rotate, and manage Data Encryption Keys (DEKs).

DEKs are used for encrypting data at rest. They are wrapped by Key Encryption Keys (KEKs)
and support hierarchical path-based organization for multi-tenant isolation.

Examples:
  # Create a new AES-256-GCM DEK
  platformctl kms dek create /tenant/myapp/default

  # Get DEK metadata
  platformctl kms dek get /tenant/myapp/default

  # List DEKs under a specific path
  platformctl kms dek list --prefix /tenant/myapp --recursive

  # Rotate a DEK
  platformctl kms dek rotate /tenant/myapp/default

  # Delete a DEK, bypassing deletion protection
  platformctl kms dek delete /tenant/myapp/default --force

  # Set safety limits
  platformctl kms dek set-safety /tenant/myapp/default --max-operations 1000000

  # Clear safety limits
  platformctl kms dek clear-safety /tenant/myapp/default --force`,
	}

	cmd.AddCommand(newDEKCreateCommand(getFlags))
	cmd.AddCommand(newDEKGetCommand(getFlags))
	cmd.AddCommand(newDEKListCommand(getFlags))
	cmd.AddCommand(newDEKDeleteCommand(getFlags))
	cmd.AddCommand(newDEKRotateCommand(getFlags))
	cmd.AddCommand(newDEKStatusCommand(getFlags))
	cmd.AddCommand(newDEKSetDefaultCommand(getFlags))
	cmd.AddCommand(newDEKSetSafetyCommand(getFlags))
	cmd.AddCommand(newDEKClearSafetyCommand(getFlags))

	return cmd
}

// dekAction is one verb's work against the SDK DEK client.
type dekAction func(ctx context.Context, client dekclient.Client, printer *cli.Printer) error

// runDEK opens the SDK DEK client for flags and runs action against it.
func runDEK(flags *cli.CommonFlags, action dekAction) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := activeDEKClientFactory(base)
	if err != nil {
		return err
	}
	return action(base.Context(), client, base.Printer())
}

// runDEKSafety runs a default or safety action on the client
// activeDEKSafetyClientFactory picks for the connection's transport.
func runDEKSafety(flags *cli.CommonFlags, action func(ctx context.Context, client dekSafetyClient, printer *cli.Printer) error) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := activeDEKSafetyClientFactory(base)
	if err != nil {
		return err
	}
	return action(base.Context(), client, base.Printer())
}

func newDEKCreateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var limits dekSafetyOptions
	cmd := &cobra.Command{
		Use:   "create <path>",
		Short: "Create a new AES-256-GCM DEK",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client dekclient.Client, printer *cli.Printer) error {
				return executeDEKCreate(ctx, client, printer, args[0], limits)
			})
		},
	}
	// A zero limit is unset: CreateDEK leaves it to the server's default.
	bindDEKSafetyFlags(cmd, &limits, 0)
	return cmd
}

func executeDEKCreate(ctx context.Context, client dekclient.Client, printer *cli.Printer, path string, limits dekSafetyOptions) error {
	resp, err := client.CreateDEK(ctx, &dekclient.CreateDEKRequest{
		Path:           path,
		Algorithm:      dekCreateAlgorithm,
		MaxOperations:  limits.MaxOperations,
		MaxBytes:       limits.MaxBytes,
		WarningPercent: int(limits.WarningPercent),
	})
	if err != nil {
		return ErrDEKOperationFailed{Verb: "create", Path: path, Err: err}
	}
	return printer.Print(newDEKOutput(resp.DEK))
}

func newDEKGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "get <path>",
		Short: "Get DEK metadata",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client dekclient.Client, printer *cli.Printer) error {
				return executeDEKGet(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKGet(ctx context.Context, client dekclient.Client, printer *cli.Printer, path string) error {
	info, err := client.GetDEK(ctx, path)
	if err != nil {
		return ErrDEKOperationFailed{Verb: "get", Path: path, Err: err}
	}
	return printer.Print(newDEKOutput(info))
}

// dekListOptions carries the `dek list` flags.
type dekListOptions struct {
	Prefix    string
	Recursive bool
	Limit     int32
	Cursor    string
}

func newDEKListCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts dekListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List DEKs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client dekclient.Client, printer *cli.Printer) error {
				return executeDEKList(ctx, client, printer, opts)
			})
		},
	}
	cmd.Flags().StringVar(&opts.Prefix, "prefix", "", "filter by path prefix")
	cmd.Flags().BoolVar(&opts.Recursive, "recursive", false, "list recursively")
	cmd.Flags().Int32Var(&opts.Limit, "limit", 100, "maximum number of results")
	cmd.Flags().StringVar(&opts.Cursor, "cursor", "", "pagination cursor (the SDK DEK client cannot page yet)")
	return cmd
}

func executeDEKList(ctx context.Context, client dekclient.Client, printer *cli.Printer, opts dekListOptions) error {
	if opts.Cursor != "" {
		return ErrDEKSDKGap{Option: "list --cursor", Missing: "ListDEKsRequest.Cursor (ListDEKs cannot page)"}
	}
	if opts.Limit <= 0 {
		return ErrInvalidDEKLimit{Limit: opts.Limit}
	}
	resp, err := client.ListDEKs(ctx, &dekclient.ListDEKsRequest{
		Prefix:    opts.Prefix,
		Recursive: opts.Recursive,
		Limit:     int(opts.Limit),
	})
	if err != nil {
		return ErrDEKOperationFailed{Verb: "list", Path: opts.Prefix, Err: err}
	}
	out := dekListOutput{DEKs: make([]dekOutput, 0, len(resp.DEKs)), TotalCount: resp.TotalCount}
	for i := range resp.DEKs {
		out.DEKs = append(out.DEKs, newDEKOutput(&resp.DEKs[i]))
	}
	return printer.Print(out)
}

func newDEKDeleteCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <path>",
		Short: "Delete a DEK",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client dekclient.Client, printer *cli.Printer) error {
				return executeDEKDelete(ctx, client, printer, args[0], force)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "bypass deletion protection")
	return cmd
}

func executeDEKDelete(ctx context.Context, client dekclient.Client, printer *cli.Printer, path string, force bool) error {
	resp, err := client.DeleteDEK(ctx, &dekclient.DeleteDEKRequest{Path: path, Force: force})
	if err != nil {
		return ErrDEKOperationFailed{Verb: "delete", Path: path, Err: err}
	}
	return printer.Print(dekDeleteOutput{Path: resp.Path, Deleted: resp.Deleted})
}

func newDEKRotateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <path>",
		Short: "Rotate a DEK to a new version",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEK(getFlags(), func(ctx context.Context, client dekclient.Client, printer *cli.Printer) error {
				return executeDEKRotate(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKRotate(ctx context.Context, client dekclient.Client, printer *cli.Printer, path string) error {
	resp, err := client.RotateDEK(ctx, &dekclient.RotateDEKRequest{Path: path})
	if err != nil {
		return ErrDEKOperationFailed{Verb: "rotate", Path: path, Err: err}
	}
	return printer.Print(dekRotateOutput{Path: resp.Path, OldVersion: resp.OldVersion, NewVersion: resp.NewVersion})
}

func newDEKStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status <path>",
		Short: "Get DEK status, AEAD usage and re-encryption progress",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			base, err := cli.NewBaseCommand(getFlags())
			if err != nil {
				return err
			}
			defer base.Close()

			source, err := activeDEKStatusSourceFactory(base)
			if err != nil {
				return err
			}
			return executeDEKStatus(base.Context(), source, base.Printer(), args[0])
		},
	}
}

func executeDEKStatus(ctx context.Context, source dekStatusSource, printer *cli.Printer, path string) error {
	out, err := source(ctx, path)
	if err != nil {
		return ErrDEKOperationFailed{Verb: "status", Path: path, Err: err}
	}
	return printer.Print(out)
}

func newDEKSetDefaultCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "set-default <path>",
		Short: "Make a DEK the default for its path level",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEKSafety(getFlags(), func(ctx context.Context, client dekSafetyClient, printer *cli.Printer) error {
				return executeDEKSetDefault(ctx, client, printer, args[0])
			})
		},
	}
}

func executeDEKSetDefault(ctx context.Context, client dekSafetyClient, printer *cli.Printer, path string) error {
	resp, err := client.SetDefaultDEK(ctx, path)
	if err != nil {
		return ErrDEKOperationFailed{Verb: "set-default", Path: path, Err: err}
	}
	return printer.Print(dekSetDefaultOutput{Path: resp.Path, PreviousDefault: resp.PreviousDefault})
}

// dekSafetyOptions carries the `dek set-safety` flags.
type dekSafetyOptions struct {
	MaxOperations  uint64
	MaxBytes       uint64
	WarningPercent int32
}

func newDEKSetSafetyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts dekSafetyOptions
	cmd := &cobra.Command{
		Use:   "set-safety <path>",
		Short: "Set DEK AEAD safety limits",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEKSafety(getFlags(), func(ctx context.Context, client dekSafetyClient, printer *cli.Printer) error {
				return executeDEKSetSafety(ctx, client, printer, args[0], opts)
			})
		},
	}
	bindDEKSafetyFlags(cmd, &opts, 80)
	return cmd
}

// bindDEKSafetyFlags binds the AEAD safety limit flags `dek create` and
// `dek set-safety` share.
func bindDEKSafetyFlags(cmd *cobra.Command, opts *dekSafetyOptions, warnPercentDefault int32) {
	cmd.Flags().Uint64Var(&opts.MaxOperations, "max-operations", 0, "max number of operations")
	cmd.Flags().Uint64Var(&opts.MaxBytes, "max-bytes", 0, "max bytes encrypted")
	cmd.Flags().Int32Var(&opts.WarningPercent, "warn-percent", warnPercentDefault, "warning threshold percentage")
}

func executeDEKSetSafety(ctx context.Context, client dekSafetyClient, printer *cli.Printer, path string, opts dekSafetyOptions) error {
	err := client.SetDEKSafety(ctx, &dekclient.SetDEKSafetyRequest{
		Path:           path,
		MaxOperations:  opts.MaxOperations,
		MaxBytes:       opts.MaxBytes,
		WarningPercent: int(opts.WarningPercent),
	})
	if err != nil {
		return ErrDEKOperationFailed{Verb: "set-safety", Path: path, Err: err}
	}
	printer.PrintSuccess(fmt.Sprintf("DEK %s safety limits set", path))
	return nil
}

func newDEKClearSafetyCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "clear-safety <path>",
		Short: "Clear DEK AEAD safety limits (requires --force)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDEKSafety(getFlags(), func(ctx context.Context, client dekSafetyClient, printer *cli.Printer) error {
				return executeDEKClearSafety(ctx, client, printer, args[0], force)
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "confirm removing the safety limits")
	return cmd
}

func executeDEKClearSafety(ctx context.Context, client dekSafetyClient, printer *cli.Printer, path string, force bool) error {
	if !force {
		return ErrDEKClearSafetyNotConfirmed{Path: path}
	}
	if err := client.ClearDEKSafety(ctx, path); err != nil {
		return ErrDEKOperationFailed{Verb: "clear-safety", Path: path, Err: err}
	}
	printer.PrintSuccess(fmt.Sprintf("DEK %s safety limits cleared", path))
	return nil
}

// formatTimestamp formats a Unix timestamp for display
func formatTimestamp(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", ts)
}
