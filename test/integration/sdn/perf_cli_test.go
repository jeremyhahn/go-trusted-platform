//go:build integration

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

package sdn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// perfCLIBridge is the dedicated bridge every perf measurement targets so
// the test never touches bridges owned by other suites.
const perfCLIBridge = "tp-perfcli"

// perfFlowsView is the protocol-neutral flow measurement result.
type perfFlowsView struct {
	Installed      uint32  `json:"installed"`
	DurationNs     int64   `json:"duration_ns"`
	FlowsPerSecond float64 `json:"flows_per_second"`
	Batched        bool    `json:"batched"`
	Bridge         string  `json:"bridge"`
}

// perfDatapathView is the protocol-neutral datapath counter result.
type perfDatapathView struct {
	Hits               uint64 `json:"hits"`
	Misses             uint64 `json:"misses"`
	Lost               uint64 `json:"lost"`
	OffloadedFlowCount uint64 `json:"offloaded_flow_count"`
	HWOffloadEnabled   bool   `json:"hw_offload_enabled"`
	DatapathType       string `json:"datapath_type"`
	Bridge             string `json:"bridge"`
}

// perfConntrackView is the protocol-neutral conntrack summary result.
type perfConntrackView struct {
	TotalEntries uint64            `json:"total_entries"`
	PerZone      map[uint32]uint64 `json:"per_zone"`
}

// perfProtocolAdapter is the common perf surface every protocol adapter
// implements for the table-driven multi-protocol test.
type perfProtocolAdapter interface {
	Name() string
	Setup(ctx context.Context) error
	Teardown() error
	PerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*perfFlowsView, error)
	PerfDatapath(ctx context.Context, bridge string) (*perfDatapathView, error)
	PerfConntrack(ctx context.Context, zone *uint32) (*perfConntrackView, error)
}

// =============================================================================
// CLI adapter — platformctl sdn gateway perf {flows,datapath,conntrack}
// =============================================================================

// perfCLIAdapter drives the real platformctl binary (local context: gRPC
// over the Unix socket).
type perfCLIAdapter struct {
	cli *CLIAdapter
}

func (a *perfCLIAdapter) Name() string { return "CLI" }

func (a *perfCLIAdapter) Setup(ctx context.Context) error {
	a.cli = NewCLIAdapter()
	return a.cli.Setup(ctx)
}

func (a *perfCLIAdapter) Teardown() error { return a.cli.Teardown() }

func (a *perfCLIAdapter) PerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*perfFlowsView, error) {
	args := []string{"sdn", "gateway", "perf", "flows", "--count", strconv.FormatUint(uint64(count), 10)}
	if batch {
		args = append(args, "--batch")
	}
	if bridge != "" {
		args = append(args, "--bridge", bridge)
	}
	out, err := a.cli.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	var view perfFlowsView
	if err := a.cli.parseJSONOutput(out, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (a *perfCLIAdapter) PerfDatapath(ctx context.Context, bridge string) (*perfDatapathView, error) {
	args := []string{"sdn", "gateway", "perf", "datapath"}
	if bridge != "" {
		args = append(args, "--bridge", bridge)
	}
	out, err := a.cli.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	var view perfDatapathView
	if err := a.cli.parseJSONOutput(out, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (a *perfCLIAdapter) PerfConntrack(ctx context.Context, zone *uint32) (*perfConntrackView, error) {
	args := []string{"sdn", "gateway", "perf", "conntrack"}
	if zone != nil {
		args = append(args, "--zone", strconv.FormatUint(uint64(*zone), 10))
	}
	out, err := a.cli.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}
	var view perfConntrackView
	if err := a.cli.parseJSONOutput(out, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

// =============================================================================
// REST adapter — /api/v1/sdn/gateway/perf/*
// =============================================================================

type perfRESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

func (a *perfRESTAdapter) Name() string { return "REST" }

func (a *perfRESTAdapter) Setup(ctx context.Context) error {
	rest := NewSDNRESTAdapter()
	a.baseURL = rest.baseURL
	a.httpClient = helpers.NewHTTPClient(60 * time.Second)
	return nil
}

func (a *perfRESTAdapter) Teardown() error {
	if a.httpClient != nil {
		a.httpClient.CloseIdleConnections()
	}
	return nil
}

// doJSON performs one HTTP round-trip decoding a JSON response.
func (a *perfRESTAdapter) doJSON(ctx context.Context, method, path string, body, out interface{}) error {
	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reqBody = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("REST %s %s: status %d: %s", method, path, resp.StatusCode, respBody)
	}
	return json.Unmarshal(respBody, out)
}

func (a *perfRESTAdapter) PerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*perfFlowsView, error) {
	request := map[string]interface{}{"count": count, "batch": batch, "bridge": bridge}
	var view perfFlowsView
	if err := a.doJSON(ctx, http.MethodPost, "/api/v1/sdn/gateway/perf/flows", request, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (a *perfRESTAdapter) PerfDatapath(ctx context.Context, bridge string) (*perfDatapathView, error) {
	path := "/api/v1/sdn/gateway/perf/datapath"
	if bridge != "" {
		path += "?bridge=" + bridge
	}
	var view perfDatapathView
	if err := a.doJSON(ctx, http.MethodGet, path, nil, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (a *perfRESTAdapter) PerfConntrack(ctx context.Context, zone *uint32) (*perfConntrackView, error) {
	path := "/api/v1/sdn/gateway/perf/conntrack"
	if zone != nil {
		path += "?zone=" + strconv.FormatUint(uint64(*zone), 10)
	}
	var view perfConntrackView
	if err := a.doJSON(ctx, http.MethodGet, path, nil, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

// =============================================================================
// gRPC family adapter — TCP gRPC and gRPC over the Unix socket
// =============================================================================

type perfGRPCAdapter struct {
	name    string
	target  func() (string, []grpc.DialOption)
	conn    *grpc.ClientConn
	gateway platformv1.GatewayServiceClient
}

// newPerfGRPCAdapter builds the TCP gRPC adapter.
func newPerfGRPCAdapter() *perfGRPCAdapter {
	return &perfGRPCAdapter{
		name: "gRPC",
		target: func() (string, []grpc.DialOption) {
			return GetServiceEndpoints().PlatformdGRPC, []grpc.DialOption{helpers.GRPCTransportCredentials()}
		},
	}
}

// newPerfUnixAdapter builds the gRPC-over-UDS adapter.
func newPerfUnixAdapter() *perfGRPCAdapter {
	return &perfGRPCAdapter{
		name: "Unix",
		target: func() (string, []grpc.DialOption) {
			return "unix://" + GetServiceEndpoints().PlatformdSock,
				[]grpc.DialOption{helpers.GRPCUnixCredentials()}
		},
	}
}

func (a *perfGRPCAdapter) Name() string { return a.name }

func (a *perfGRPCAdapter) Setup(ctx context.Context) error {
	endpoint, opts := a.target()
	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return ErrAdapterSetupFailed{Protocol: a.name, Err: err}
	}
	a.conn = conn
	a.gateway = platformv1.NewGatewayServiceClient(conn)
	return nil
}

func (a *perfGRPCAdapter) Teardown() error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

func (a *perfGRPCAdapter) PerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*perfFlowsView, error) {
	resp, err := a.gateway.GetPerfFlows(ctx, &platformv1.GetPerfFlowsRequest{Count: count, Batch: batch, Bridge: bridge})
	if err != nil {
		return nil, err
	}
	return &perfFlowsView{
		Installed:      resp.GetInstalled(),
		DurationNs:     resp.GetDurationNs(),
		FlowsPerSecond: resp.GetFlowsPerSecond(),
		Batched:        resp.GetBatched(),
		Bridge:         resp.GetBridge(),
	}, nil
}

func (a *perfGRPCAdapter) PerfDatapath(ctx context.Context, bridge string) (*perfDatapathView, error) {
	resp, err := a.gateway.GetPerfDatapath(ctx, &platformv1.GetPerfDatapathRequest{Bridge: bridge})
	if err != nil {
		return nil, err
	}
	return &perfDatapathView{
		Hits:               resp.GetHits(),
		Misses:             resp.GetMisses(),
		Lost:               resp.GetLost(),
		OffloadedFlowCount: resp.GetOffloadedFlowCount(),
		HWOffloadEnabled:   resp.GetHwOffloadEnabled(),
		DatapathType:       resp.GetDatapathType(),
		Bridge:             resp.GetBridge(),
	}, nil
}

func (a *perfGRPCAdapter) PerfConntrack(ctx context.Context, zone *uint32) (*perfConntrackView, error) {
	resp, err := a.gateway.GetPerfConntrack(ctx, &platformv1.GetPerfConntrackRequest{Zone: zone})
	if err != nil {
		return nil, err
	}
	return &perfConntrackView{TotalEntries: resp.GetTotalEntries(), PerZone: resp.GetPerZone()}, nil
}

// =============================================================================
// QUIC adapter — gateway category (0x2F), perf sub-opcodes 0x36-0x38
// =============================================================================

// QUIC perf wire structs: msgpack keys map on Go field names, mirroring
// pkg/api/quic/gateway_perf_handlers.go.
type quicPerfFlowsRequest struct {
	Count  uint32
	Batch  bool
	Bridge string
}

type quicPerfFlowsInfo struct {
	Installed      uint32
	DurationNs     int64
	FlowsPerSecond float64
	Batched        bool
	Bridge         string
}

type quicPerfDatapathRequest struct {
	Bridge string
}

type quicPerfDatapathInfo struct {
	Hits               uint64
	Misses             uint64
	Lost               uint64
	OffloadedFlowCount uint64
	HwOffloadEnabled   bool
	DatapathType       string
	Bridge             string
}

type quicPerfConntrackRequest struct {
	Zone *uint32
}

type quicPerfConntrackInfo struct {
	TotalEntries uint64
	PerZone      map[uint32]uint64
}

// Perf sub-opcodes under the gateway category (0x2F).
const (
	quicOpPerfFlows     byte = 0x36
	quicOpPerfDatapath  byte = 0x37
	quicOpPerfConntrack byte = 0x38
)

type perfQUICAdapter struct {
	quic *SDNQUICAdapter
}

func (a *perfQUICAdapter) Name() string { return "QUIC" }

func (a *perfQUICAdapter) Setup(ctx context.Context) error {
	a.quic = NewSDNQUICAdapter()
	return a.quic.Setup(ctx)
}

func (a *perfQUICAdapter) Teardown() error { return a.quic.Teardown() }

func (a *perfQUICAdapter) PerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*perfFlowsView, error) {
	payload, err := a.quic.sendCategoryRequest(ctx, opGatewayCategory, quicOpPerfFlows,
		&quicPerfFlowsRequest{Count: count, Batch: batch, Bridge: bridge})
	if err != nil {
		return nil, err
	}
	var info quicPerfFlowsInfo
	if err := quicDecode(payload, &info); err != nil {
		return nil, err
	}
	return &perfFlowsView{
		Installed:      info.Installed,
		DurationNs:     info.DurationNs,
		FlowsPerSecond: info.FlowsPerSecond,
		Batched:        info.Batched,
		Bridge:         info.Bridge,
	}, nil
}

func (a *perfQUICAdapter) PerfDatapath(ctx context.Context, bridge string) (*perfDatapathView, error) {
	payload, err := a.quic.sendCategoryRequest(ctx, opGatewayCategory, quicOpPerfDatapath,
		&quicPerfDatapathRequest{Bridge: bridge})
	if err != nil {
		return nil, err
	}
	var info quicPerfDatapathInfo
	if err := quicDecode(payload, &info); err != nil {
		return nil, err
	}
	return &perfDatapathView{
		Hits:               info.Hits,
		Misses:             info.Misses,
		Lost:               info.Lost,
		OffloadedFlowCount: info.OffloadedFlowCount,
		HWOffloadEnabled:   info.HwOffloadEnabled,
		DatapathType:       info.DatapathType,
		Bridge:             info.Bridge,
	}, nil
}

func (a *perfQUICAdapter) PerfConntrack(ctx context.Context, zone *uint32) (*perfConntrackView, error) {
	payload, err := a.quic.sendCategoryRequest(ctx, opGatewayCategory, quicOpPerfConntrack,
		&quicPerfConntrackRequest{Zone: zone})
	if err != nil {
		return nil, err
	}
	var info quicPerfConntrackInfo
	if err := quicDecode(payload, &info); err != nil {
		return nil, err
	}
	return &perfConntrackView{TotalEntries: info.TotalEntries, PerZone: info.PerZone}, nil
}

// =============================================================================
// MCP adapter — gateway_perf_* tools
// =============================================================================

type perfMCPAdapter struct {
	mcp *SDNMCPAdapter
}

func (a *perfMCPAdapter) Name() string { return "MCP" }

func (a *perfMCPAdapter) Setup(ctx context.Context) error {
	a.mcp = NewSDNMCPAdapter()
	return a.mcp.Setup(ctx)
}

func (a *perfMCPAdapter) Teardown() error { return a.mcp.Teardown() }

func (a *perfMCPAdapter) PerfFlows(ctx context.Context, count uint32, batch bool, bridge string) (*perfFlowsView, error) {
	params := map[string]interface{}{"count": count, "batch": batch}
	if bridge != "" {
		params["bridge"] = bridge
	}
	result, err := a.mcp.callTool(ctx, "gateway_perf_flows", params)
	if err != nil {
		return nil, err
	}
	var view perfFlowsView
	if err := json.Unmarshal(result, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (a *perfMCPAdapter) PerfDatapath(ctx context.Context, bridge string) (*perfDatapathView, error) {
	params := map[string]interface{}{}
	if bridge != "" {
		params["bridge"] = bridge
	}
	result, err := a.mcp.callTool(ctx, "gateway_perf_datapath", params)
	if err != nil {
		return nil, err
	}
	var view perfDatapathView
	if err := json.Unmarshal(result, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

func (a *perfMCPAdapter) PerfConntrack(ctx context.Context, zone *uint32) (*perfConntrackView, error) {
	params := map[string]interface{}{}
	if zone != nil {
		params["zone"] = *zone
	}
	result, err := a.mcp.callTool(ctx, "gateway_perf_conntrack", params)
	if err != nil {
		return nil, err
	}
	var view perfConntrackView
	if err := json.Unmarshal(result, &view); err != nil {
		return nil, err
	}
	return &view, nil
}

// =============================================================================
// Multi-protocol test
// =============================================================================

// setupPerfBridge creates the dedicated measurement bridge on the
// daemon's OVS instance.
func setupPerfBridge(t *testing.T) {
	t.Helper()
	exec.Command("ovs-vsctl", "--if-exists", "del-br", perfCLIBridge).Run()
	runCmd(t, "ovs-vsctl", "add-br", perfCLIBridge)
	runCmd(t, "ovs-vsctl", "set", "bridge", perfCLIBridge, "protocols=OpenFlow13")
	t.Cleanup(func() {
		runCmdQuiet("ovs-vsctl", "--if-exists", "del-br", perfCLIBridge)
	})
}

// TestGatewayPerfMultiProtocol exercises the perf command surface over
// every protocol against the running platformd. All reported values are
// real measurements produced by the daemon against the live OVS.
func TestGatewayPerfMultiProtocol(t *testing.T) {
	requireOVSForTest(t)

	setupPerfBridge(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	adapters := []perfProtocolAdapter{
		&perfCLIAdapter{},
		&perfRESTAdapter{},
		newPerfGRPCAdapter(),
		&perfQUICAdapter{},
		&perfMCPAdapter{},
		newPerfUnixAdapter(),
	}

	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("%s setup: %v", adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("%s teardown: %v", adapter.Name(), err)
				}
			})
			testPerfProtocol(ctx, t, adapter)
		})
	}
}

// testPerfProtocol is the shared per-protocol assertion set.
func testPerfProtocol(ctx context.Context, t *testing.T, adapter perfProtocolAdapter) {
	t.Run("FlowsBatched", func(t *testing.T) {
		view, err := adapter.PerfFlows(ctx, 50, true, perfCLIBridge)
		require.NoError(t, err, "perf flows --batch")
		require.Equal(t, uint32(50), view.Installed)
		require.True(t, view.Batched)
		require.Equal(t, perfCLIBridge, view.Bridge)
		require.Greater(t, view.DurationNs, int64(0), "measured duration must be positive")
		require.Greater(t, view.FlowsPerSecond, 0.0, "measured rate must be positive")
		assertPerfTableEmpty(t)
	})

	t.Run("FlowsSequential", func(t *testing.T) {
		view, err := adapter.PerfFlows(ctx, 20, false, perfCLIBridge)
		require.NoError(t, err, "perf flows sequential")
		require.Equal(t, uint32(20), view.Installed)
		require.False(t, view.Batched)
		require.Greater(t, view.DurationNs, int64(0))
		assertPerfTableEmpty(t)
	})

	t.Run("FlowsInvalidCount", func(t *testing.T) {
		_, err := adapter.PerfFlows(ctx, 200000, true, perfCLIBridge)
		require.Error(t, err, "counts above the limit must be rejected")
	})

	t.Run("Datapath", func(t *testing.T) {
		view, err := adapter.PerfDatapath(ctx, perfCLIBridge)
		require.NoError(t, err, "perf datapath")
		require.NotEmpty(t, view.DatapathType, "datapath type must be reported")
		require.Equal(t, perfCLIBridge, view.Bridge)
	})

	t.Run("ConntrackAllZones", func(t *testing.T) {
		view, err := adapter.PerfConntrack(ctx, nil)
		require.NoError(t, err, "perf conntrack")
		var sum uint64
		for _, count := range view.PerZone {
			sum += count
		}
		require.Equal(t, view.TotalEntries, sum, "per-zone counts must sum to the total")
	})

	t.Run("ConntrackSpecificZone", func(t *testing.T) {
		zone := uint32(1)
		_, err := adapter.PerfConntrack(ctx, &zone)
		require.NoError(t, err, "perf conntrack --zone 1")
	})
}

// assertPerfTableEmpty verifies the measurement left no flows behind in
// the dedicated perf table (250).
func assertPerfTableEmpty(t *testing.T) {
	t.Helper()
	out := runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", perfCLIBridge, "table=250")
	for _, line := range bytes.Split([]byte(out), []byte("\n")) {
		if bytes.Contains(line, []byte("table=250")) {
			t.Fatalf("perf table 250 not cleaned up: %s", line)
		}
	}
}
