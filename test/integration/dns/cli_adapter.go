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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface using the platformctl CLI binary.

//go:build integration

package dns

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLICommandFailed is returned when a CLI command fails to execute.
type ErrCLICommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLICommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("CLI command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("CLI command %q failed: %v", e.Command, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrCLICommandFailed) Unwrap() error { return e.Err }

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// ErrCLIOutputInvalid is returned when a command's -o json output is not the
// DNSService response it should be.
type ErrCLIOutputInvalid struct {
	Command string
	Err     error
}

func (e ErrCLIOutputInvalid) Error() string {
	return fmt.Sprintf("CLI command %q printed an invalid response: %v", e.Command, e.Err)
}

// Unwrap returns the underlying error.
func (e ErrCLIOutputInvalid) Unwrap() error { return e.Err }

// ErrCLIRecordUnsupported is returned for a record the dns record verbs have
// no flags for.
type ErrCLIRecordUnsupported struct {
	Type pb.RecordType
}

func (e ErrCLIRecordUnsupported) Error() string {
	return fmt.Sprintf("platformctl dns record has no flags for a %s record", e.Type)
}

// =============================================================================
// CLI Adapter
// =============================================================================

// CLIAdapter is the DNS suite's CLI leg: every operation runs a
// `platformctl -o json dns ...` verb and reads the DNSService response it
// prints. The operations themselves are GRPCAdapter's, run over cliDNSClient,
// so the CLI leg asserts exactly what the other legs assert.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	configDir      string
	configPath     string
	commandTimeout time.Duration

	// ops runs the DNS operations over cliDNSClient.
	ops *GRPCAdapter
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// It reads the binary path from PLATFORMCTL_BINARY env var or uses the default.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformctlBinary)
	if binaryPath == "" {
		binaryPath = DefaultPlatformctlBinary
	}

	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}

	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		commandTimeout: DefaultCommandTimeout,
	}
}

// Name returns the protocol name for this adapter.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup writes the harness CLI config and verifies `dns zone list` runs.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	dir, path, err := helpers.WriteTempLocalCLIConfig(c.socketPath, helpers.GetGRPCEndpoint())
	if err != nil {
		return err
	}
	c.configDir, c.configPath = dir, path
	c.ops = &GRPCAdapter{dns: cliDNSClient{adapter: c}}

	if _, err := c.runCommand(ctx, "dns", "zone", "list"); err != nil {
		return err
	}
	return nil
}

// Teardown removes the config file Setup wrote.
func (c *CLIAdapter) Teardown() error {
	if c.configDir == "" {
		return nil
	}
	return os.RemoveAll(c.configDir)
}

// runCommand executes platformctl with the harness config and JSON output
// and returns stdout.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	// platformctl has no --socket flag; the harness socket reaches it through
	// the config file Setup wrote (#540).
	fullArgs := append([]string{"--config", c.configPath, "-o", "json"}, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

func (c *CLIAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	return c.ops.CreateZone(ctx, opts)
}

func (c *CLIAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	return c.ops.GetZone(ctx, zoneName)
}

func (c *CLIAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	return c.ops.UpdateZone(ctx, zoneName, opts)
}

func (c *CLIAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	return c.ops.DeleteZone(ctx, zoneName)
}

func (c *CLIAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	return c.ops.ListZones(ctx, opts)
}

func (c *CLIAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	return c.ops.AddRecord(ctx, opts)
}

func (c *CLIAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	return c.ops.GetRecord(ctx, name, recordType)
}

func (c *CLIAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	return c.ops.UpdateRecord(ctx, opts)
}

func (c *CLIAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	return c.ops.DeleteRecord(ctx, name, recordType)
}

func (c *CLIAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	return c.ops.ListRecords(ctx, zoneName, opts)
}

func (c *CLIAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	return c.ops.Resolve(ctx, name, recordType)
}

func (c *CLIAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	return c.ops.AddTLSARecord(ctx, opts)
}

// Compile-time check that CLIAdapter implements DNSCommands.
var _ DNSCommands = (*CLIAdapter)(nil)

// =============================================================================
// DNSService over platformctl
// =============================================================================

// cliDNSClient is the DNSService over the platformctl dns verbs.
type cliDNSClient struct {
	adapter *CLIAdapter
}

// cliProtoJSON reads the responses `-o json` prints.
var cliProtoJSON = protojson.UnmarshalOptions{DiscardUnknown: true}

// run executes one dns verb and reads the response it prints.
func (c cliDNSClient) run(ctx context.Context, response proto.Message, args ...string) error {
	out, err := c.adapter.runCommand(ctx, append([]string{"dns"}, args...)...)
	if err != nil {
		return err
	}
	if err := cliProtoJSON.Unmarshal(out, response); err != nil {
		return ErrCLIOutputInvalid{Command: strings.Join(args, " "), Err: err}
	}
	return nil
}

// cliUint renders a uint32 flag value.
func cliUint(v uint32) string {
	return strconv.FormatUint(uint64(v), 10)
}

// paginationArgs renders a pagination request as flags.
func paginationArgs(p *pb.PaginationRequest) []string {
	if p == nil {
		return nil
	}
	return []string{"--page", cliUint(p.GetPage()), "--page-size", cliUint(p.GetPageSize())}
}

// recordArgs renders a record as the dns record add/update flags.
func recordArgs(record *pb.Record) ([]string, error) {
	args := []string{"--type", strings.TrimPrefix(record.GetType().String(), "RECORD_TYPE_")}
	switch r := record.GetRecord().(type) {
	case *pb.Record_A:
		args = append(args, "--name", r.A.GetName(), "--value", r.A.GetValue(), "--ttl", cliUint(r.A.GetTtl()))
	case *pb.Record_Aaaa:
		args = append(args, "--name", r.Aaaa.GetName(), "--value", r.Aaaa.GetValue(), "--ttl", cliUint(r.Aaaa.GetTtl()))
	case *pb.Record_Cname:
		args = append(args, "--name", r.Cname.GetName(), "--value", r.Cname.GetValue(), "--ttl", cliUint(r.Cname.GetTtl()))
	case *pb.Record_Mx:
		args = append(args, "--name", r.Mx.GetName(), "--value", r.Mx.GetValue(), "--ttl", cliUint(r.Mx.GetTtl()),
			"--priority", cliUint(r.Mx.GetPriority()))
	case *pb.Record_Ns:
		args = append(args, "--name", r.Ns.GetName(), "--value", r.Ns.GetValue(), "--ttl", cliUint(r.Ns.GetTtl()))
	case *pb.Record_Txt:
		args = append(args, "--name", r.Txt.GetName(), "--value", r.Txt.GetValue(), "--ttl", cliUint(r.Txt.GetTtl()))
	case *pb.Record_Srv:
		args = append(args, "--name", r.Srv.GetName(), "--value", r.Srv.GetTarget(), "--ttl", cliUint(r.Srv.GetTtl()),
			"--priority", cliUint(r.Srv.GetPriority()), "--weight", cliUint(r.Srv.GetWeight()), "--port", cliUint(r.Srv.GetPort()))
	case *pb.Record_Caa:
		args = append(args, "--name", r.Caa.GetName(), "--value", r.Caa.GetValue(), "--ttl", cliUint(r.Caa.GetTtl()),
			"--flags", cliUint(r.Caa.GetFlags()), "--tag", r.Caa.GetTag())
	case *pb.Record_Tlsa:
		args = append(args, "--name", r.Tlsa.GetName(), "--value", r.Tlsa.GetData(), "--ttl", cliUint(r.Tlsa.GetTtl()),
			"--usage", cliUint(r.Tlsa.GetUsage()), "--selector", cliUint(r.Tlsa.GetSelector()),
			"--matching-type", cliUint(r.Tlsa.GetMatchingType()))
	default:
		return nil, ErrCLIRecordUnsupported{Type: record.GetType()}
	}
	return args, nil
}

func (c cliDNSClient) CreateZone(ctx context.Context, in *pb.CreateZoneRequest, _ ...grpc.CallOption) (*pb.CreateZoneResponse, error) {
	args := []string{"zone", "create", in.GetName(), "--ttl", cliUint(in.GetTtl()), "--description", in.GetDescription()}
	if in.GetInternal() {
		args = append(args, "--internal")
	}
	if soa := in.GetSoa(); soa != nil {
		args = append(args, "--soa-mname", soa.GetMname(), "--soa-rname", soa.GetRname(),
			"--soa-serial", cliUint(soa.GetSerial()), "--soa-refresh", cliUint(soa.GetRefresh()),
			"--soa-retry", cliUint(soa.GetRetry()), "--soa-expire", cliUint(soa.GetExpire()),
			"--soa-minimum-ttl", cliUint(soa.GetMinimumTtl()))
	}
	for _, ns := range in.GetNsRecords() {
		args = append(args, "--ns", ns.GetValue())
	}
	out := &pb.CreateZoneResponse{}
	return out, c.run(ctx, out, args...)
}

func (c cliDNSClient) GetZone(ctx context.Context, in *pb.GetZoneRequest, _ ...grpc.CallOption) (*pb.GetZoneResponse, error) {
	out := &pb.GetZoneResponse{}
	return out, c.run(ctx, out, "zone", "get", in.GetName())
}

func (c cliDNSClient) UpdateZone(ctx context.Context, in *pb.UpdateZoneRequest, _ ...grpc.CallOption) (*pb.UpdateZoneResponse, error) {
	out := &pb.UpdateZoneResponse{}
	return out, c.run(ctx, out, "zone", "update", in.GetName(), "--ttl", cliUint(in.GetTtl()), "--description", in.GetDescription())
}

func (c cliDNSClient) DeleteZone(ctx context.Context, in *pb.DeleteZoneRequest, _ ...grpc.CallOption) (*pb.DeleteZoneResponse, error) {
	out := &pb.DeleteZoneResponse{}
	return out, c.run(ctx, out, "zone", "delete", in.GetName())
}

func (c cliDNSClient) ListZones(ctx context.Context, in *pb.ListZonesRequest, _ ...grpc.CallOption) (*pb.ListZonesResponse, error) {
	args := []string{"zone", "list"}
	if in.GetInternalOnly() {
		args = append(args, "--internal-only")
	}
	if in.GetPublicOnly() {
		args = append(args, "--public-only")
	}
	args = append(args, paginationArgs(in.GetPagination())...)
	out := &pb.ListZonesResponse{}
	return out, c.run(ctx, out, args...)
}

func (c cliDNSClient) AddRecord(ctx context.Context, in *pb.AddRecordRequest, _ ...grpc.CallOption) (*pb.AddRecordResponse, error) {
	flags, err := recordArgs(in.GetRecord())
	if err != nil {
		return nil, err
	}
	out := &pb.AddRecordResponse{}
	return out, c.run(ctx, out, append([]string{"record", "add", in.GetZoneName()}, flags...)...)
}

func (c cliDNSClient) DeleteRecord(ctx context.Context, in *pb.DeleteRecordRequest, _ ...grpc.CallOption) (*pb.DeleteRecordResponse, error) {
	out := &pb.DeleteRecordResponse{}
	return out, c.run(ctx, out, "record", "delete", in.GetZoneName(),
		"--type", strings.TrimPrefix(in.GetType().String(), "RECORD_TYPE_"), "--name", in.GetName())
}

// UpdateRecord sends the new record; `dns record update` finds the old one by
// the same type and name, as the service does.
func (c cliDNSClient) UpdateRecord(ctx context.Context, in *pb.UpdateRecordRequest, _ ...grpc.CallOption) (*pb.UpdateRecordResponse, error) {
	flags, err := recordArgs(in.GetNewRecord())
	if err != nil {
		return nil, err
	}
	out := &pb.UpdateRecordResponse{}
	return out, c.run(ctx, out, append([]string{"record", "update", in.GetZoneName()}, flags...)...)
}

func (c cliDNSClient) ListRecords(ctx context.Context, in *pb.ListRecordsRequest, _ ...grpc.CallOption) (*pb.ListRecordsResponse, error) {
	args := []string{"record", "list", in.GetZoneName()}
	if in.GetType() != pb.RecordType_RECORD_TYPE_UNSPECIFIED {
		args = append(args, "--type", strings.TrimPrefix(in.GetType().String(), "RECORD_TYPE_"))
	}
	args = append(args, paginationArgs(in.GetPagination())...)
	out := &pb.ListRecordsResponse{}
	return out, c.run(ctx, out, args...)
}

func (c cliDNSClient) SignZone(ctx context.Context, in *pb.SignZoneRequest, _ ...grpc.CallOption) (*pb.SignZoneResponse, error) {
	out := &pb.SignZoneResponse{}
	return out, c.run(ctx, out, "dnssec", "sign", in.GetZoneName())
}

func (c cliDNSClient) GetDNSSECStatus(ctx context.Context, in *pb.GetDNSSECStatusRequest, _ ...grpc.CallOption) (*pb.GetDNSSECStatusResponse, error) {
	out := &pb.GetDNSSECStatusResponse{}
	return out, c.run(ctx, out, "dnssec", "status", in.GetZoneName())
}

func (c cliDNSClient) Resolve(ctx context.Context, in *pb.ResolveRequest, _ ...grpc.CallOption) (*pb.ResolveResponse, error) {
	args := []string{"resolve", in.GetFqdn()}
	if in.GetType() != pb.RecordType_RECORD_TYPE_UNSPECIFIED {
		args = append(args, "--type", strings.TrimPrefix(in.GetType().String(), "RECORD_TYPE_"))
	}
	out := &pb.ResolveResponse{}
	return out, c.run(ctx, out, args...)
}

func (c cliDNSClient) Register(ctx context.Context, in *pb.RegisterRequest, _ ...grpc.CallOption) (*pb.RegisterResponse, error) {
	out := &pb.RegisterResponse{}
	return out, c.run(ctx, out, "register", in.GetFqdn(), in.GetIp())
}

// Compile-time check that cliDNSClient is a DNSService client.
var _ pb.DNSServiceClient = cliDNSClient{}
