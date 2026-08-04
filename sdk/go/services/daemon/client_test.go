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

package daemon

import (
	"context"
	"errors"
	"io"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"google.golang.org/grpc"
)

// mockPlatformDaemonClient implements platformv1.PlatformDaemonClient for testing.
type mockPlatformDaemonClient struct {
	platformv1.PlatformDaemonClient

	getStatusResp    *platformv1.GetStatusResponse
	getStatusErr     error
	getHealthResp    *platformv1.GetHealthResponse
	getHealthErr     error
	getVersionResp   *platformv1.GetVersionResponse
	getVersionErr    error
	getConfigResp    *platformv1.GetConfigResponse
	getConfigErr     error
	updateConfigResp *platformv1.UpdateConfigResponse
	updateConfigErr  error
	reloadConfigResp *platformv1.ReloadConfigResponse
	reloadConfigErr  error
	shutdownResp     *platformv1.ShutdownResponse
	shutdownErr      error

	startServiceResp     *platformv1.StartServiceResponse
	startServiceErr      error
	stopServiceResp      *platformv1.StopServiceResponse
	stopServiceErr       error
	restartServiceResp   *platformv1.RestartServiceResponse
	restartServiceErr    error
	getServiceStatusResp *platformv1.GetServiceStatusResponse
	getServiceStatusErr  error
	listServicesResp     *platformv1.ListServicesResponse
	listServicesErr      error

	listEntityTypesResp *platformv1.ListEntityTypesResponse
	listEntityTypesErr  error

	streamEventsStream   *mockEventStream
	streamEventsErr      error
	streamLogsStream     *mockLogStream
	streamLogsErr        error
	streamMetricsStream  *mockMetricStream
	streamMetricsErr     error
	dumpEntityTypeStream *mockEntityDumpStream
	dumpEntityTypeErr    error
}

func (m *mockPlatformDaemonClient) GetStatus(ctx context.Context, in *platformv1.GetStatusRequest, opts ...grpc.CallOption) (*platformv1.GetStatusResponse, error) {
	return m.getStatusResp, m.getStatusErr
}

func (m *mockPlatformDaemonClient) GetHealth(ctx context.Context, in *platformv1.GetHealthRequest, opts ...grpc.CallOption) (*platformv1.GetHealthResponse, error) {
	return m.getHealthResp, m.getHealthErr
}

func (m *mockPlatformDaemonClient) GetVersion(ctx context.Context, in *platformv1.GetVersionRequest, opts ...grpc.CallOption) (*platformv1.GetVersionResponse, error) {
	return m.getVersionResp, m.getVersionErr
}

func (m *mockPlatformDaemonClient) GetConfig(ctx context.Context, in *platformv1.GetConfigRequest, opts ...grpc.CallOption) (*platformv1.GetConfigResponse, error) {
	return m.getConfigResp, m.getConfigErr
}

func (m *mockPlatformDaemonClient) UpdateConfig(ctx context.Context, in *platformv1.UpdateConfigRequest, opts ...grpc.CallOption) (*platformv1.UpdateConfigResponse, error) {
	return m.updateConfigResp, m.updateConfigErr
}

func (m *mockPlatformDaemonClient) ReloadConfig(ctx context.Context, in *platformv1.ReloadConfigRequest, opts ...grpc.CallOption) (*platformv1.ReloadConfigResponse, error) {
	return m.reloadConfigResp, m.reloadConfigErr
}

func (m *mockPlatformDaemonClient) Shutdown(ctx context.Context, in *platformv1.ShutdownRequest, opts ...grpc.CallOption) (*platformv1.ShutdownResponse, error) {
	return m.shutdownResp, m.shutdownErr
}

func (m *mockPlatformDaemonClient) StartService(ctx context.Context, in *platformv1.StartServiceRequest, opts ...grpc.CallOption) (*platformv1.StartServiceResponse, error) {
	return m.startServiceResp, m.startServiceErr
}

func (m *mockPlatformDaemonClient) StopService(ctx context.Context, in *platformv1.StopServiceRequest, opts ...grpc.CallOption) (*platformv1.StopServiceResponse, error) {
	return m.stopServiceResp, m.stopServiceErr
}

func (m *mockPlatformDaemonClient) RestartService(ctx context.Context, in *platformv1.RestartServiceRequest, opts ...grpc.CallOption) (*platformv1.RestartServiceResponse, error) {
	return m.restartServiceResp, m.restartServiceErr
}

func (m *mockPlatformDaemonClient) GetServiceStatus(ctx context.Context, in *platformv1.GetServiceStatusRequest, opts ...grpc.CallOption) (*platformv1.GetServiceStatusResponse, error) {
	return m.getServiceStatusResp, m.getServiceStatusErr
}

func (m *mockPlatformDaemonClient) ListServices(ctx context.Context, in *platformv1.ListServicesRequest, opts ...grpc.CallOption) (*platformv1.ListServicesResponse, error) {
	return m.listServicesResp, m.listServicesErr
}

func (m *mockPlatformDaemonClient) ListEntityTypes(ctx context.Context, in *platformv1.ListEntityTypesRequest, opts ...grpc.CallOption) (*platformv1.ListEntityTypesResponse, error) {
	return m.listEntityTypesResp, m.listEntityTypesErr
}

func (m *mockPlatformDaemonClient) StreamEvents(ctx context.Context, in *platformv1.StreamEventsRequest, opts ...grpc.CallOption) (platformv1.PlatformDaemon_StreamEventsClient, error) {
	if m.streamEventsErr != nil {
		return nil, m.streamEventsErr
	}
	return m.streamEventsStream, nil
}

func (m *mockPlatformDaemonClient) StreamLogs(ctx context.Context, in *platformv1.StreamLogsRequest, opts ...grpc.CallOption) (platformv1.PlatformDaemon_StreamLogsClient, error) {
	if m.streamLogsErr != nil {
		return nil, m.streamLogsErr
	}
	return m.streamLogsStream, nil
}

func (m *mockPlatformDaemonClient) StreamMetrics(ctx context.Context, in *platformv1.StreamMetricsRequest, opts ...grpc.CallOption) (platformv1.PlatformDaemon_StreamMetricsClient, error) {
	if m.streamMetricsErr != nil {
		return nil, m.streamMetricsErr
	}
	return m.streamMetricsStream, nil
}

func (m *mockPlatformDaemonClient) DumpEntityType(ctx context.Context, in *platformv1.DumpEntityTypeRequest, opts ...grpc.CallOption) (platformv1.PlatformDaemon_DumpEntityTypeClient, error) {
	if m.dumpEntityTypeErr != nil {
		return nil, m.dumpEntityTypeErr
	}
	return m.dumpEntityTypeStream, nil
}

// Mock stream implementations
type mockEventStream struct {
	platformv1.PlatformDaemon_StreamEventsClient
	events []*platformv1.Event
	index  int
	err    error
}

func (m *mockEventStream) Recv() (*platformv1.Event, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.events) {
		return nil, io.EOF
	}
	event := m.events[m.index]
	m.index++
	return event, nil
}

func (m *mockEventStream) CloseSend() error {
	return nil
}

type mockLogStream struct {
	platformv1.PlatformDaemon_StreamLogsClient
	entries []*platformv1.LogEntry
	index   int
	err     error
}

func (m *mockLogStream) Recv() (*platformv1.LogEntry, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.entries) {
		return nil, io.EOF
	}
	entry := m.entries[m.index]
	m.index++
	return entry, nil
}

func (m *mockLogStream) CloseSend() error {
	return nil
}

type mockMetricStream struct {
	platformv1.PlatformDaemon_StreamMetricsClient
	metrics []*platformv1.MetricData
	index   int
	err     error
}

func (m *mockMetricStream) Recv() (*platformv1.MetricData, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.metrics) {
		return nil, io.EOF
	}
	metric := m.metrics[m.index]
	m.index++
	return metric, nil
}

func (m *mockMetricStream) CloseSend() error {
	return nil
}

type mockEntityDumpStream struct {
	platformv1.PlatformDaemon_DumpEntityTypeClient
	responses []*platformv1.DumpEntityTypeResponse
	index     int
	err       error
}

func (m *mockEntityDumpStream) Recv() (*platformv1.DumpEntityTypeResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.responses) {
		return nil, io.EOF
	}
	resp := m.responses[m.index]
	m.index++
	return resp, nil
}

func (m *mockEntityDumpStream) CloseSend() error {
	return nil
}

func TestNewClient(t *testing.T) {
	t.Run("returns error for nil connection", func(t *testing.T) {
		client, err := NewClient(nil)
		if err != common.ErrNilConnection {
			t.Errorf("NewClient(nil) error = %v, want %v", err, common.ErrNilConnection)
		}
		if client != nil {
			t.Error("NewClient(nil) should return nil client")
		}
	})
}

func TestNewClientFromGRPC(t *testing.T) {
	t.Run("creates client from gRPC client", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{}
		client := NewClientFromGRPC(mockGRPC)
		if client == nil {
			t.Fatal("NewClientFromGRPC() returned nil")
		}
		if client.grpc != mockGRPC {
			t.Error("NewClientFromGRPC() did not set grpc client correctly")
		}
	})
}

func TestClient_GetVersion(t *testing.T) {
	t.Run("returns version info successfully", func(t *testing.T) {
		expectedResp := &platformv1.GetVersionResponse{
			Version:   "1.0.0",
			BuildTime: "2025-01-01T00:00:00Z",
			GitCommit: "abc123",
			GoVersion: "go1.25",
		}
		mockGRPC := &mockPlatformDaemonClient{getVersionResp: expectedResp}
		client := NewClientFromGRPC(mockGRPC)

		resp, err := client.GetVersion(context.Background())
		if err != nil {
			t.Fatalf("GetVersion() error = %v", err)
		}
		if resp.Version != expectedResp.Version {
			t.Errorf("Version = %v, want %v", resp.Version, expectedResp.Version)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{getVersionErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetVersion(context.Background())
		if err == nil {
			t.Fatal("GetVersion() should return error")
		}
		var versionErr *ErrGetVersionFailed
		if !errors.As(err, &versionErr) {
			t.Errorf("error type = %T, want *ErrGetVersionFailed", err)
		}
	})
}

func TestClient_GetStatus(t *testing.T) {
	t.Run("returns status successfully", func(t *testing.T) {
		expectedResp := &platformv1.GetStatusResponse{
			Status: platformv1.SystemStatus_SYSTEM_STATUS_READY,
			Info: &platformv1.PlatformInfo{
				Hostname: "test-host",
				Version:  "1.0.0",
				SystemInfo: &platformv1.SystemInfo{
					Os:   "linux",
					Arch: "amd64",
				},
				TpmInfo: &platformv1.TPMInfo{
					Manufacturer: "test-mfr",
				},
			},
		}
		mockGRPC := &mockPlatformDaemonClient{getStatusResp: expectedResp}
		client := NewClientFromGRPC(mockGRPC)

		resp, err := client.GetStatus(context.Background())
		if err != nil {
			t.Fatalf("GetStatus() error = %v", err)
		}
		if resp.Info.Hostname != "test-host" {
			t.Errorf("Hostname = %v, want test-host", resp.Info.Hostname)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{getStatusErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetStatus(context.Background())
		if err == nil {
			t.Fatal("GetStatus() should return error")
		}
		var statusErr *ErrGetStatusFailed
		if !errors.As(err, &statusErr) {
			t.Errorf("error type = %T, want *ErrGetStatusFailed", err)
		}
	})
}

func TestClient_GetSystemInfo(t *testing.T) {
	t.Run("returns system info successfully", func(t *testing.T) {
		expectedInfo := &platformv1.SystemInfo{
			Os:            "linux",
			Arch:          "amd64",
			KernelVersion: "5.15.0",
			NumCpus:       8,
			TotalMemoryMb: 16384,
		}
		mockGRPC := &mockPlatformDaemonClient{
			getStatusResp: &platformv1.GetStatusResponse{
				Info: &platformv1.PlatformInfo{
					SystemInfo: expectedInfo,
				},
			},
		}
		client := NewClientFromGRPC(mockGRPC)

		info, err := client.GetSystemInfo(context.Background())
		if err != nil {
			t.Fatalf("GetSystemInfo() error = %v", err)
		}
		if info.Os != expectedInfo.Os {
			t.Errorf("Os = %v, want %v", info.Os, expectedInfo.Os)
		}
		if info.NumCpus != expectedInfo.NumCpus {
			t.Errorf("NumCpus = %v, want %v", info.NumCpus, expectedInfo.NumCpus)
		}
	})

	t.Run("returns error when info is nil", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			getStatusResp: &platformv1.GetStatusResponse{Info: nil},
		}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetSystemInfo(context.Background())
		if err == nil {
			t.Fatal("GetSystemInfo() should return error when info is nil")
		}
		var infoErr *ErrGetSystemInfoFailed
		if !errors.As(err, &infoErr) {
			t.Errorf("error type = %T, want *ErrGetSystemInfoFailed", err)
		}
	})

	t.Run("returns error when system_info is nil", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			getStatusResp: &platformv1.GetStatusResponse{
				Info: &platformv1.PlatformInfo{SystemInfo: nil},
			},
		}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetSystemInfo(context.Background())
		if err == nil {
			t.Fatal("GetSystemInfo() should return error when system_info is nil")
		}
	})
}

func TestClient_GetTPMInfo(t *testing.T) {
	t.Run("returns TPM info successfully", func(t *testing.T) {
		expectedInfo := &platformv1.TPMInfo{
			Manufacturer:    "test-mfr",
			FirmwareVersion: "1.2.3",
			IsSimulator:     false,
		}
		mockGRPC := &mockPlatformDaemonClient{
			getStatusResp: &platformv1.GetStatusResponse{
				Info: &platformv1.PlatformInfo{
					TpmInfo: expectedInfo,
				},
			},
		}
		client := NewClientFromGRPC(mockGRPC)

		info, err := client.GetTPMInfo(context.Background())
		if err != nil {
			t.Fatalf("GetTPMInfo() error = %v", err)
		}
		if info.Manufacturer != expectedInfo.Manufacturer {
			t.Errorf("Manufacturer = %v, want %v", info.Manufacturer, expectedInfo.Manufacturer)
		}
	})

	t.Run("returns error when tpm_info is nil", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			getStatusResp: &platformv1.GetStatusResponse{
				Info: &platformv1.PlatformInfo{TpmInfo: nil},
			},
		}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetTPMInfo(context.Background())
		if err == nil {
			t.Fatal("GetTPMInfo() should return error when tpm_info is nil")
		}
		var infoErr *ErrGetTPMInfoFailed
		if !errors.As(err, &infoErr) {
			t.Errorf("error type = %T, want *ErrGetTPMInfoFailed", err)
		}
	})
}

func TestClient_GetHealth(t *testing.T) {
	t.Run("returns health status successfully", func(t *testing.T) {
		expectedResp := &platformv1.GetHealthResponse{
			Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY,
			Components: []*platformv1.ComponentHealth{
				{Name: "tpm", Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
				{Name: "ca", Status: platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
			},
		}
		mockGRPC := &mockPlatformDaemonClient{getHealthResp: expectedResp}
		client := NewClientFromGRPC(mockGRPC)

		resp, err := client.GetHealth(context.Background(), true)
		if err != nil {
			t.Fatalf("GetHealth() error = %v", err)
		}
		if resp.Status != platformv1.HealthStatus_HEALTH_STATUS_HEALTHY {
			t.Errorf("Status = %v, want HEALTH_STATUS_HEALTHY", resp.Status)
		}
		if len(resp.Components) != 2 {
			t.Errorf("len(Components) = %d, want 2", len(resp.Components))
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{getHealthErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetHealth(context.Background(), false)
		if err == nil {
			t.Fatal("GetHealth() should return error")
		}
		var healthErr *ErrGetHealthFailed
		if !errors.As(err, &healthErr) {
			t.Errorf("error type = %T, want *ErrGetHealthFailed", err)
		}
	})
}

func TestClient_GetConfig(t *testing.T) {
	t.Run("returns all config sections", func(t *testing.T) {
		expectedSections := []*platformv1.ConfigSection{
			{Section: "logging", Values: map[string]string{"level": "info"}},
			{Section: "tpm", Values: map[string]string{"enabled": "true"}},
		}
		mockGRPC := &mockPlatformDaemonClient{
			getConfigResp: &platformv1.GetConfigResponse{Sections: expectedSections},
		}
		client := NewClientFromGRPC(mockGRPC)

		sections, err := client.GetConfig(context.Background(), "")
		if err != nil {
			t.Fatalf("GetConfig() error = %v", err)
		}
		if len(sections) != 2 {
			t.Errorf("len(sections) = %d, want 2", len(sections))
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{getConfigErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetConfig(context.Background(), "")
		if err == nil {
			t.Fatal("GetConfig() should return error")
		}
		var configErr *ErrGetConfigFailed
		if !errors.As(err, &configErr) {
			t.Errorf("error type = %T, want *ErrGetConfigFailed", err)
		}
	})
}

func TestClient_UpdateConfig(t *testing.T) {
	t.Run("updates config successfully", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			updateConfigResp: &platformv1.UpdateConfigResponse{},
		}
		client := NewClientFromGRPC(mockGRPC)

		err := client.UpdateConfig(context.Background(), &platformv1.ConfigSection{
			Section: "logging",
			Values:  map[string]string{"level": "debug"},
		}, true)
		if err != nil {
			t.Fatalf("UpdateConfig() error = %v", err)
		}
	})

	t.Run("returns error for nil section", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{}
		client := NewClientFromGRPC(mockGRPC)

		err := client.UpdateConfig(context.Background(), nil, true)
		if err == nil {
			t.Fatal("UpdateConfig() should return error for nil section")
		}
		var updateErr *ErrUpdateConfigFailed
		if !errors.As(err, &updateErr) {
			t.Errorf("error type = %T, want *ErrUpdateConfigFailed", err)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{updateConfigErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		err := client.UpdateConfig(context.Background(), &platformv1.ConfigSection{
			Section: "logging",
		}, false)
		if err == nil {
			t.Fatal("UpdateConfig() should return error")
		}
	})
}

func TestClient_ReloadConfig(t *testing.T) {
	t.Run("reloads config successfully", func(t *testing.T) {
		expectedSections := []string{"logging", "tpm"}
		mockGRPC := &mockPlatformDaemonClient{
			reloadConfigResp: &platformv1.ReloadConfigResponse{ReloadedSections: expectedSections},
		}
		client := NewClientFromGRPC(mockGRPC)

		sections, err := client.ReloadConfig(context.Background())
		if err != nil {
			t.Fatalf("ReloadConfig() error = %v", err)
		}
		if len(sections) != 2 {
			t.Errorf("len(sections) = %d, want 2", len(sections))
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{reloadConfigErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.ReloadConfig(context.Background())
		if err == nil {
			t.Fatal("ReloadConfig() should return error")
		}
		var reloadErr *ErrReloadConfigFailed
		if !errors.As(err, &reloadErr) {
			t.Errorf("error type = %T, want *ErrReloadConfigFailed", err)
		}
	})
}

func TestClient_Shutdown(t *testing.T) {
	t.Run("shuts down successfully", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{shutdownResp: &platformv1.ShutdownResponse{}}
		client := NewClientFromGRPC(mockGRPC)

		err := client.Shutdown(context.Background(), true, 30)
		if err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{shutdownErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		err := client.Shutdown(context.Background(), true, 30)
		if err == nil {
			t.Fatal("Shutdown() should return error")
		}
		var shutdownErr *ErrShutdownFailed
		if !errors.As(err, &shutdownErr) {
			t.Errorf("error type = %T, want *ErrShutdownFailed", err)
		}
	})
}

func TestClient_Restart(t *testing.T) {
	t.Run("restarts all running services", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			listServicesResp: &platformv1.ListServicesResponse{
				Services: []*platformv1.ServiceInfo{
					{Type: platformv1.ServiceType_SERVICE_TYPE_TPM, Name: "tpm"},
					{Type: platformv1.ServiceType_SERVICE_TYPE_SDN, Name: "sdn"},
				},
			},
			restartServiceResp: &platformv1.RestartServiceResponse{
				Service: &platformv1.ServiceInfo{Status: platformv1.ServiceStatus_SERVICE_STATUS_RUNNING},
			},
		}
		client := NewClientFromGRPC(mockGRPC)

		err := client.Restart(context.Background(), 30)
		if err != nil {
			t.Fatalf("Restart() error = %v", err)
		}
	})

	t.Run("returns error when list services fails", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			listServicesErr: errors.New("rpc error"),
		}
		client := NewClientFromGRPC(mockGRPC)

		err := client.Restart(context.Background(), 30)
		if err == nil {
			t.Fatal("Restart() should return error")
		}
		var restartErr *ErrRestartFailed
		if !errors.As(err, &restartErr) {
			t.Errorf("error type = %T, want *ErrRestartFailed", err)
		}
	})

	t.Run("returns error when restart service fails", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			listServicesResp: &platformv1.ListServicesResponse{
				Services: []*platformv1.ServiceInfo{
					{Type: platformv1.ServiceType_SERVICE_TYPE_TPM, Name: "tpm"},
				},
			},
			restartServiceErr: errors.New("restart failed"),
		}
		client := NewClientFromGRPC(mockGRPC)

		err := client.Restart(context.Background(), 30)
		if err == nil {
			t.Fatal("Restart() should return error")
		}
	})
}

func TestClient_StartService(t *testing.T) {
	t.Run("starts service successfully", func(t *testing.T) {
		expectedService := &platformv1.ServiceInfo{
			Type:   platformv1.ServiceType_SERVICE_TYPE_TPM,
			Name:   "tpm",
			Status: platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
		}
		mockGRPC := &mockPlatformDaemonClient{
			startServiceResp: &platformv1.StartServiceResponse{Service: expectedService},
		}
		client := NewClientFromGRPC(mockGRPC)

		service, err := client.StartService(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM, nil)
		if err != nil {
			t.Fatalf("StartService() error = %v", err)
		}
		if service.Status != platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
			t.Errorf("Status = %v, want RUNNING", service.Status)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{startServiceErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.StartService(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM, nil)
		if err == nil {
			t.Fatal("StartService() should return error")
		}
		var startErr *ErrStartServiceFailed
		if !errors.As(err, &startErr) {
			t.Errorf("error type = %T, want *ErrStartServiceFailed", err)
		}
	})
}

func TestClient_StopService(t *testing.T) {
	t.Run("stops service successfully", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{stopServiceResp: &platformv1.StopServiceResponse{}}
		client := NewClientFromGRPC(mockGRPC)

		err := client.StopService(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM, false, 30)
		if err != nil {
			t.Fatalf("StopService() error = %v", err)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{stopServiceErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		err := client.StopService(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM, false, 30)
		if err == nil {
			t.Fatal("StopService() should return error")
		}
		var stopErr *ErrStopServiceFailed
		if !errors.As(err, &stopErr) {
			t.Errorf("error type = %T, want *ErrStopServiceFailed", err)
		}
	})
}

func TestClient_RestartService(t *testing.T) {
	t.Run("restarts service successfully", func(t *testing.T) {
		expectedService := &platformv1.ServiceInfo{
			Type:   platformv1.ServiceType_SERVICE_TYPE_TPM,
			Status: platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
		}
		mockGRPC := &mockPlatformDaemonClient{
			restartServiceResp: &platformv1.RestartServiceResponse{Service: expectedService},
		}
		client := NewClientFromGRPC(mockGRPC)

		service, err := client.RestartService(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM, 30)
		if err != nil {
			t.Fatalf("RestartService() error = %v", err)
		}
		if service.Status != platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
			t.Errorf("Status = %v, want RUNNING", service.Status)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{restartServiceErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.RestartService(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM, 30)
		if err == nil {
			t.Fatal("RestartService() should return error")
		}
		var restartErr *ErrRestartServiceFailed
		if !errors.As(err, &restartErr) {
			t.Errorf("error type = %T, want *ErrRestartServiceFailed", err)
		}
	})
}

func TestClient_GetServiceStatus(t *testing.T) {
	t.Run("gets service status successfully", func(t *testing.T) {
		expectedService := &platformv1.ServiceInfo{
			Type:   platformv1.ServiceType_SERVICE_TYPE_TPM,
			Status: platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
		}
		mockGRPC := &mockPlatformDaemonClient{
			getServiceStatusResp: &platformv1.GetServiceStatusResponse{Service: expectedService},
		}
		client := NewClientFromGRPC(mockGRPC)

		service, err := client.GetServiceStatus(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM)
		if err != nil {
			t.Fatalf("GetServiceStatus() error = %v", err)
		}
		if service.Status != platformv1.ServiceStatus_SERVICE_STATUS_RUNNING {
			t.Errorf("Status = %v, want RUNNING", service.Status)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{getServiceStatusErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.GetServiceStatus(context.Background(), platformv1.ServiceType_SERVICE_TYPE_TPM)
		if err == nil {
			t.Fatal("GetServiceStatus() should return error")
		}
		var statusErr *ErrGetServiceStatusFailed
		if !errors.As(err, &statusErr) {
			t.Errorf("error type = %T, want *ErrGetServiceStatusFailed", err)
		}
	})
}

func TestClient_ListServices(t *testing.T) {
	t.Run("lists services successfully", func(t *testing.T) {
		expectedServices := []*platformv1.ServiceInfo{
			{Type: platformv1.ServiceType_SERVICE_TYPE_TPM, Name: "tpm"},
			{Type: platformv1.ServiceType_SERVICE_TYPE_SDN, Name: "sdn"},
		}
		mockGRPC := &mockPlatformDaemonClient{
			listServicesResp: &platformv1.ListServicesResponse{Services: expectedServices},
		}
		client := NewClientFromGRPC(mockGRPC)

		services, err := client.ListServices(context.Background(), nil, nil)
		if err != nil {
			t.Fatalf("ListServices() error = %v", err)
		}
		if len(services) != 2 {
			t.Errorf("len(services) = %d, want 2", len(services))
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{listServicesErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.ListServices(context.Background(), nil, nil)
		if err == nil {
			t.Fatal("ListServices() should return error")
		}
		var listErr *ErrListServicesFailed
		if !errors.As(err, &listErr) {
			t.Errorf("error type = %T, want *ErrListServicesFailed", err)
		}
	})
}

func TestClient_ListEntityTypes(t *testing.T) {
	t.Run("lists entity types successfully", func(t *testing.T) {
		expectedResp := &platformv1.ListEntityTypesResponse{
			EntityTypes: []*platformv1.EntityTypeInfo{
				{Name: "users", EntityCount: 100},
				{Name: "devices", EntityCount: 50},
			},
			TotalEntities: 150,
		}
		mockGRPC := &mockPlatformDaemonClient{listEntityTypesResp: expectedResp}
		client := NewClientFromGRPC(mockGRPC)

		resp, err := client.ListEntityTypes(context.Background())
		if err != nil {
			t.Fatalf("ListEntityTypes() error = %v", err)
		}
		if len(resp.EntityTypes) != 2 {
			t.Errorf("len(EntityTypes) = %d, want 2", len(resp.EntityTypes))
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{listEntityTypesErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.ListEntityTypes(context.Background())
		if err == nil {
			t.Fatal("ListEntityTypes() should return error")
		}
		var listErr *ErrListEntityTypesFailed
		if !errors.As(err, &listErr) {
			t.Errorf("error type = %T, want *ErrListEntityTypesFailed", err)
		}
	})
}

func TestClient_StreamEvents(t *testing.T) {
	t.Run("opens event stream successfully", func(t *testing.T) {
		expectedEvents := []*platformv1.Event{
			{Id: "1", Type: platformv1.EventType_EVENT_TYPE_SYSTEM_STARTUP},
			{Id: "2", Type: platformv1.EventType_EVENT_TYPE_SERVICE_STARTED},
		}
		mockGRPC := &mockPlatformDaemonClient{
			streamEventsStream: &mockEventStream{events: expectedEvents},
		}
		client := NewClientFromGRPC(mockGRPC)

		stream, err := client.StreamEvents(context.Background(), nil)
		if err != nil {
			t.Fatalf("StreamEvents() error = %v", err)
		}

		event, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v", err)
		}
		if event.Id != "1" {
			t.Errorf("event.Id = %v, want 1", event.Id)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{streamEventsErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.StreamEvents(context.Background(), nil)
		if err == nil {
			t.Fatal("StreamEvents() should return error")
		}
		var streamErr *ErrStreamEventsFailed
		if !errors.As(err, &streamErr) {
			t.Errorf("error type = %T, want *ErrStreamEventsFailed", err)
		}
	})
}

func TestClient_StreamLogs(t *testing.T) {
	t.Run("opens log stream successfully", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			streamLogsStream: &mockLogStream{entries: []*platformv1.LogEntry{}},
		}
		client := NewClientFromGRPC(mockGRPC)

		stream, err := client.StreamLogs(context.Background(), nil)
		if err != nil {
			t.Fatalf("StreamLogs() error = %v", err)
		}
		if stream == nil {
			t.Fatal("StreamLogs() returned nil stream")
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{streamLogsErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.StreamLogs(context.Background(), nil)
		if err == nil {
			t.Fatal("StreamLogs() should return error")
		}
		var streamErr *ErrStreamLogsFailed
		if !errors.As(err, &streamErr) {
			t.Errorf("error type = %T, want *ErrStreamLogsFailed", err)
		}
	})
}

func TestClient_StreamMetrics(t *testing.T) {
	t.Run("opens metrics stream successfully", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			streamMetricsStream: &mockMetricStream{metrics: []*platformv1.MetricData{}},
		}
		client := NewClientFromGRPC(mockGRPC)

		stream, err := client.StreamMetrics(context.Background(), nil)
		if err != nil {
			t.Fatalf("StreamMetrics() error = %v", err)
		}
		if stream == nil {
			t.Fatal("StreamMetrics() returned nil stream")
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{streamMetricsErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.StreamMetrics(context.Background(), nil)
		if err == nil {
			t.Fatal("StreamMetrics() should return error")
		}
		var streamErr *ErrStreamMetricsFailed
		if !errors.As(err, &streamErr) {
			t.Errorf("error type = %T, want *ErrStreamMetricsFailed", err)
		}
	})
}

func TestClient_DumpEntityType(t *testing.T) {
	t.Run("opens entity dump stream successfully", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{
			dumpEntityTypeStream: &mockEntityDumpStream{
				responses: []*platformv1.DumpEntityTypeResponse{
					{EntityType: "users", EntityId: 1, Data: []byte(`{"id":1}`)},
				},
			},
		}
		client := NewClientFromGRPC(mockGRPC)

		stream, err := client.DumpEntityType(context.Background(), "users", "json", true)
		if err != nil {
			t.Fatalf("DumpEntityType() error = %v", err)
		}

		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv() error = %v", err)
		}
		if resp.EntityType != "users" {
			t.Errorf("EntityType = %v, want users", resp.EntityType)
		}
	})

	t.Run("returns error on gRPC failure", func(t *testing.T) {
		mockGRPC := &mockPlatformDaemonClient{dumpEntityTypeErr: errors.New("rpc error")}
		client := NewClientFromGRPC(mockGRPC)

		_, err := client.DumpEntityType(context.Background(), "users", "json", true)
		if err == nil {
			t.Fatal("DumpEntityType() should return error")
		}
		var dumpErr *ErrDumpEntityTypeFailed
		if !errors.As(err, &dumpErr) {
			t.Errorf("error type = %T, want *ErrDumpEntityTypeFailed", err)
		}
	})
}

func TestEventStreamAdapter_Recv(t *testing.T) {
	t.Run("returns EOF when stream ends", func(t *testing.T) {
		stream := &mockEventStream{events: []*platformv1.Event{}}
		adapter := &eventStreamAdapter{stream: stream}

		_, err := adapter.Recv()
		if err != io.EOF {
			t.Errorf("Recv() error = %v, want io.EOF", err)
		}
	})

	t.Run("wraps stream errors", func(t *testing.T) {
		stream := &mockEventStream{err: errors.New("stream error")}
		adapter := &eventStreamAdapter{stream: stream}

		_, err := adapter.Recv()
		if err == nil {
			t.Fatal("Recv() should return error")
		}
		var recvErr *ErrStreamRecvFailed
		if !errors.As(err, &recvErr) {
			t.Errorf("error type = %T, want *ErrStreamRecvFailed", err)
		}
	})
}

func TestInterfaceCompliance(t *testing.T) {
	t.Run("Client implements PlatformClient", func(t *testing.T) {
		var _ PlatformClient = (*Client)(nil)
	})
}
