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
	"bytes"
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// MockPrinter implements a mock Printer interface for testing
type MockPrinter struct {
	PrintFunc         func(v interface{}) error
	PrintKeyValueFunc func(key, value string)
	PrintSuccessFunc  func(message string)
	PrintInfoFunc     func(message string)
	PrintWarningFunc  func(message string)
	PrintErrorFunc    func(message string)
	Output            *bytes.Buffer
}

func (m *MockPrinter) Print(v interface{}) error {
	if m.PrintFunc != nil {
		return m.PrintFunc(v)
	}
	return nil
}

func (m *MockPrinter) PrintKeyValue(key, value string) {
	if m.PrintKeyValueFunc != nil {
		m.PrintKeyValueFunc(key, value)
	}
}

func (m *MockPrinter) PrintSuccess(message string) {
	if m.PrintSuccessFunc != nil {
		m.PrintSuccessFunc(message)
	}
}

func (m *MockPrinter) PrintInfo(message string) {
	if m.PrintInfoFunc != nil {
		m.PrintInfoFunc(message)
	}
}

func (m *MockPrinter) PrintWarning(message string) {
	if m.PrintWarningFunc != nil {
		m.PrintWarningFunc(message)
	}
}

func (m *MockPrinter) PrintError(message string) {
	if m.PrintErrorFunc != nil {
		m.PrintErrorFunc(message)
	}
}

// MockContainerClient implements ComputeServiceClient for container testing
type MockContainerClient struct {
	CreateContainerFunc     func(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error)
	StartContainerFunc      func(ctx context.Context, in *platformv1.StartContainerRequest, opts ...grpc.CallOption) (*platformv1.StartContainerResponse, error)
	StopContainerFunc       func(ctx context.Context, in *platformv1.StopContainerRequest, opts ...grpc.CallOption) (*platformv1.StopContainerResponse, error)
	DeleteContainerFunc     func(ctx context.Context, in *platformv1.DeleteContainerRequest, opts ...grpc.CallOption) (*platformv1.DeleteContainerResponse, error)
	GetContainerFunc        func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error)
	ListContainersFunc      func(ctx context.Context, in *platformv1.ListContainersRequest, opts ...grpc.CallOption) (*platformv1.ListContainersResponse, error)
	GetContainerLogsFunc    func(ctx context.Context, in *platformv1.GetContainerLogsRequest, opts ...grpc.CallOption) (platformv1.ComputeService_GetContainerLogsClient, error)
	GetContainerMetricsFunc func(ctx context.Context, in *platformv1.GetContainerMetricsRequest, opts ...grpc.CallOption) (*platformv1.ContainerMetricsResponse, error)
}

func (m *MockContainerClient) CreateContainer(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error) {
	if m.CreateContainerFunc != nil {
		return m.CreateContainerFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) StartContainer(ctx context.Context, in *platformv1.StartContainerRequest, opts ...grpc.CallOption) (*platformv1.StartContainerResponse, error) {
	if m.StartContainerFunc != nil {
		return m.StartContainerFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) StopContainer(ctx context.Context, in *platformv1.StopContainerRequest, opts ...grpc.CallOption) (*platformv1.StopContainerResponse, error) {
	if m.StopContainerFunc != nil {
		return m.StopContainerFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) DeleteContainer(ctx context.Context, in *platformv1.DeleteContainerRequest, opts ...grpc.CallOption) (*platformv1.DeleteContainerResponse, error) {
	if m.DeleteContainerFunc != nil {
		return m.DeleteContainerFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) GetContainer(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
	if m.GetContainerFunc != nil {
		return m.GetContainerFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) ListContainers(ctx context.Context, in *platformv1.ListContainersRequest, opts ...grpc.CallOption) (*platformv1.ListContainersResponse, error) {
	if m.ListContainersFunc != nil {
		return m.ListContainersFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) GetContainerLogs(ctx context.Context, in *platformv1.GetContainerLogsRequest, opts ...grpc.CallOption) (platformv1.ComputeService_GetContainerLogsClient, error) {
	if m.GetContainerLogsFunc != nil {
		return m.GetContainerLogsFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *MockContainerClient) GetContainerMetrics(ctx context.Context, in *platformv1.GetContainerMetricsRequest, opts ...grpc.CallOption) (*platformv1.ContainerMetricsResponse, error) {
	if m.GetContainerMetricsFunc != nil {
		return m.GetContainerMetricsFunc(ctx, in, opts...)
	}
	return nil, errors.New("not implemented")
}

// ContainerCommandExecutor holds dependencies for container command execution
type ContainerCommandExecutor struct {
	Client       *MockContainerClient
	Printer      *cli.Printer
	Ctx          context.Context
	OutputFormat cli.OutputFormat
}

// executeCreate executes the container create operation with the given executor
func executeCreate(exec *ContainerCommandExecutor, config *platformv1.ContainerConfig, start bool) error {
	req := &platformv1.CreateContainerRequest{
		Config: config,
		Start:  start,
	}

	resp, err := exec.Client.CreateContainer(exec.Ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "create", ID: config.Name, Err: err}
	}

	return printCreateResponse(exec.Printer, exec.OutputFormat, resp)
}

func printCreateResponse(printer *cli.Printer, format cli.OutputFormat, resp *platformv1.CreateContainerResponse) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)
	case cli.OutputFormatTable:
		printContainerDetails(printer, computesvc.ContainerFromProto(resp.Container))
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeStart executes the container start operation with the given executor
func executeStart(exec *ContainerCommandExecutor, containerID string) error {
	req := &platformv1.StartContainerRequest{
		Id: containerID,
	}

	resp, err := exec.Client.StartContainer(exec.Ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "start", ID: containerID, Err: err}
	}

	return printStartResponse(exec.Printer, exec.OutputFormat, resp, containerID)
}

func printStartResponse(printer *cli.Printer, format cli.OutputFormat, resp *platformv1.StartContainerResponse, containerID string) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)
	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess("Container started successfully: " + containerID)
		} else if resp.Status != nil {
			printer.PrintError("Failed to start container: " + resp.Status.Message)
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeStop executes the container stop operation with the given executor
func executeStop(exec *ContainerCommandExecutor, containerID string, timeout uint32) error {
	req := &platformv1.StopContainerRequest{
		Id:             containerID,
		TimeoutSeconds: timeout,
	}

	resp, err := exec.Client.StopContainer(exec.Ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "stop", ID: containerID, Err: err}
	}

	return printStopResponse(exec.Printer, exec.OutputFormat, resp, containerID)
}

func printStopResponse(printer *cli.Printer, format cli.OutputFormat, resp *platformv1.StopContainerResponse, containerID string) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)
	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess("Container stopped successfully: " + containerID)
		} else if resp.Status != nil {
			printer.PrintError("Failed to stop container: " + resp.Status.Message)
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeRemove executes the container remove operation with the given executor
func executeRemove(exec *ContainerCommandExecutor, containerID string, force bool, deleteVolumes bool) error {
	req := &platformv1.DeleteContainerRequest{
		Id:            containerID,
		Force:         force,
		DeleteVolumes: deleteVolumes,
	}

	resp, err := exec.Client.DeleteContainer(exec.Ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "remove", ID: containerID, Err: err}
	}

	return printRemoveResponse(exec.Printer, exec.OutputFormat, resp, containerID)
}

func printRemoveResponse(printer *cli.Printer, format cli.OutputFormat, resp *platformv1.DeleteContainerResponse, containerID string) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)
	case cli.OutputFormatTable:
		if resp.Status != nil && resp.Status.Success {
			printer.PrintSuccess("Container removed successfully: " + containerID)
		} else if resp.Status != nil {
			printer.PrintError("Failed to remove container: " + resp.Status.Message)
		}
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeGet executes the container get operation with the given executor
func executeGet(exec *ContainerCommandExecutor, containerID string) error {
	req := &platformv1.GetContainerRequest{
		Id: containerID,
	}

	resp, err := exec.Client.GetContainer(exec.Ctx, req)
	if err != nil {
		return ErrContainerNotFound{ID: containerID}
	}

	return printGetResponse(exec.Printer, exec.OutputFormat, resp)
}

func printGetResponse(printer *cli.Printer, format cli.OutputFormat, resp *platformv1.GetContainerResponse) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp.Container)
	case cli.OutputFormatTable:
		return printFullContainerDetails(printer, computesvc.ContainerFromProto(resp.Container))
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeList executes the container list operation with the given executor
func executeList(exec *ContainerCommandExecutor, all bool, pageSize int32, filters []string) error {
	req := &platformv1.ListContainersRequest{
		Pagination: &platformv1.PaginationRequest{
			PageSize: uint32(pageSize),
		},
	}

	if !all {
		req.States = []platformv1.ContainerState{
			platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		}
	}

	if len(filters) > 0 {
		selector, states, err := parseFilters(filters)
		if err != nil {
			return err
		}
		if len(selector) > 0 {
			req.Selector = &platformv1.LabelSelector{MatchLabels: selector}
		}
		if len(states) > 0 {
			protoStates := make([]platformv1.ContainerState, len(states))
			for i, s := range states {
				protoStates[i] = computesvc.ContainerStateToProto(s)
			}
			req.States = protoStates
		}
	}

	resp, err := exec.Client.ListContainers(exec.Ctx, req)
	if err != nil {
		return ErrContainerOperationFailed{Operation: "list", ID: "", Err: err}
	}

	return printListResponse(exec.Printer, exec.OutputFormat, resp)
}

func printListResponse(printer *cli.Printer, format cli.OutputFormat, resp *platformv1.ListContainersResponse) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(resp)
	case cli.OutputFormatTable:
		sdkContainers := make([]*computesvc.Container, len(resp.Containers))
		for i, c := range resp.Containers {
			sdkContainers[i] = computesvc.ContainerFromProto(c)
		}
		sdkResult := &computesvc.ListContainersResult{Containers: sdkContainers}
		return printContainerList(printer, sdkResult)
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// executeAttest executes the container attest operation with the given executor
func executeAttest(exec *ContainerCommandExecutor, containerID string, nonce []byte, pcrIndices []uint32) error {
	// First verify the container exists
	getReq := &platformv1.GetContainerRequest{
		Id: containerID,
	}

	containerResp, err := exec.Client.GetContainer(exec.Ctx, getReq)
	if err != nil {
		return ErrContainerNotFound{ID: containerID}
	}

	result := &containerAttestationResult{
		ContainerID:   containerID,
		ContainerName: "",
		ImageID:       "",
		ImageDigest:   "",
		State:         formatContainerState(computesvc.ContainerStateFromProto(containerResp.Container.State)),
		Nonce:         string(nonce),
		PCRIndices:    pcrIndices,
	}

	if containerResp.Container.Config != nil {
		result.ContainerName = containerResp.Container.Config.Name
		result.ImageID = containerResp.Container.Config.Image
		result.ImageDigest = containerResp.Container.Config.ImageHash
	}

	return printAttestResponse(exec.Printer, exec.OutputFormat, result, containerID)
}

func printAttestResponse(printer *cli.Printer, format cli.OutputFormat, result *containerAttestationResult, containerID string) error {
	switch format {
	case cli.OutputFormatJSON, cli.OutputFormatYAML:
		return printer.Print(result)
	case cli.OutputFormatTable:
		printer.PrintSuccess("Container attestation collected: " + containerID)
		printer.PrintKeyValue("Container ID", result.ContainerID)
		printer.PrintKeyValue("Name", result.ContainerName)
		printer.PrintKeyValue("Image", result.ImageID)
		if result.ImageDigest != "" {
			printer.PrintKeyValue("Image Digest", result.ImageDigest)
		}
		printer.PrintKeyValue("State", result.State)
		return nil
	default:
		return cli.ErrInvalidOutputFormat{Format: string(format)}
	}
}

// Helper function to create a test container
func createTestContainer(id, name, image string, state platformv1.ContainerState) *platformv1.Container {
	return &platformv1.Container{
		Id:    id,
		State: state,
		Config: &platformv1.ContainerConfig{
			Name:      name,
			Image:     image,
			ImageHash: "sha256:abc123def456",
		},
		CreatedAt: timestamppb.Now(),
	}
}

// Tests for executeCreate
func TestExecuteCreate_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		config  *platformv1.ContainerConfig
		start   bool
		resp    *platformv1.CreateContainerResponse
		wantErr bool
	}{
		{
			name:   "basic container - table format",
			format: cli.OutputFormatTable,
			config: &platformv1.ContainerConfig{
				Name:  "test-container",
				Image: "nginx:latest",
			},
			start: false,
			resp: &platformv1.CreateContainerResponse{
				Container: createTestContainer("container-123", "test-container", "nginx:latest", platformv1.ContainerState_CONTAINER_STATE_CREATED),
			},
			wantErr: false,
		},
		{
			name:   "container with start - JSON format",
			format: cli.OutputFormatJSON,
			config: &platformv1.ContainerConfig{
				Name:  "web-app",
				Image: "myapp:v1.0",
				Env: []*platformv1.EnvVar{
					{Name: "DB_HOST", Value: "localhost"},
				},
			},
			start: true,
			resp: &platformv1.CreateContainerResponse{
				Container: createTestContainer("container-456", "web-app", "myapp:v1.0", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
			},
			wantErr: false,
		},
		{
			name:   "container with resources - YAML format",
			format: cli.OutputFormatYAML,
			config: &platformv1.ContainerConfig{
				Name:  "worker",
				Image: "worker:latest",
				Resources: &platformv1.ResourceLimits{
					MaxMemoryMb: 512,
					MaxCpus:     2,
				},
			},
			start: false,
			resp: &platformv1.CreateContainerResponse{
				Container: createTestContainer("container-789", "worker", "worker:latest", platformv1.ContainerState_CONTAINER_STATE_CREATED),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				CreateContainerFunc: func(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error) {
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeCreate(exec, tt.config, tt.start)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeCreate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteCreate_ClientError(t *testing.T) {
	expectedErr := errors.New("connection refused")
	mockClient := &MockContainerClient{
		CreateContainerFunc: func(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error) {
			return nil, expectedErr
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	config := &platformv1.ContainerConfig{
		Name:  "test-container",
		Image: "nginx:latest",
	}

	err := executeCreate(exec, config, false)

	if err == nil {
		t.Error("expected error for client failure")
	}
	if _, ok := err.(ErrContainerOperationFailed); !ok {
		t.Errorf("expected ErrContainerOperationFailed, got %T", err)
	}
}

func TestExecuteCreate_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		CreateContainerFunc: func(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error) {
			return &platformv1.CreateContainerResponse{
				Container: createTestContainer("container-123", "test", "nginx", platformv1.ContainerState_CONTAINER_STATE_CREATED),
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	config := &platformv1.ContainerConfig{
		Name:  "test",
		Image: "nginx",
	}

	err := executeCreate(exec, config, false)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for executeStart
func TestExecuteStart_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		resp    *platformv1.StartContainerResponse
		wantErr bool
	}{
		{
			name:   "successful start - table format",
			format: cli.OutputFormatTable,
			resp: &platformv1.StartContainerResponse{
				Status: &platformv1.Status{
					Success: true,
					Message: "Container started",
				},
			},
			wantErr: false,
		},
		{
			name:   "successful start - JSON format",
			format: cli.OutputFormatJSON,
			resp: &platformv1.StartContainerResponse{
				Status: &platformv1.Status{
					Success: true,
				},
			},
			wantErr: false,
		},
		{
			name:   "failed start - table format",
			format: cli.OutputFormatTable,
			resp: &platformv1.StartContainerResponse{
				Status: &platformv1.Status{
					Success: false,
					Message: "Container already running",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				StartContainerFunc: func(ctx context.Context, in *platformv1.StartContainerRequest, opts ...grpc.CallOption) (*platformv1.StartContainerResponse, error) {
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeStart(exec, "container-123")

			if (err != nil) != tt.wantErr {
				t.Errorf("executeStart() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteStart_ClientError(t *testing.T) {
	mockClient := &MockContainerClient{
		StartContainerFunc: func(ctx context.Context, in *platformv1.StartContainerRequest, opts ...grpc.CallOption) (*platformv1.StartContainerResponse, error) {
			return nil, errors.New("container not found")
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeStart(exec, "nonexistent")

	if err == nil {
		t.Error("expected error for nonexistent container")
	}
	if _, ok := err.(ErrContainerOperationFailed); !ok {
		t.Errorf("expected ErrContainerOperationFailed, got %T", err)
	}
}

func TestExecuteStart_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		StartContainerFunc: func(ctx context.Context, in *platformv1.StartContainerRequest, opts ...grpc.CallOption) (*platformv1.StartContainerResponse, error) {
			return &platformv1.StartContainerResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	err := executeStart(exec, "container-123")

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for executeStop
func TestExecuteStop_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		timeout uint32
		resp    *platformv1.StopContainerResponse
		wantErr bool
	}{
		{
			name:    "successful stop - table format",
			format:  cli.OutputFormatTable,
			timeout: 10,
			resp: &platformv1.StopContainerResponse{
				Status: &platformv1.Status{
					Success: true,
					Message: "Container stopped",
				},
			},
			wantErr: false,
		},
		{
			name:    "successful stop with custom timeout - JSON format",
			format:  cli.OutputFormatJSON,
			timeout: 30,
			resp: &platformv1.StopContainerResponse{
				Status: &platformv1.Status{
					Success: true,
				},
			},
			wantErr: false,
		},
		{
			name:    "failed stop - table format",
			format:  cli.OutputFormatTable,
			timeout: 10,
			resp: &platformv1.StopContainerResponse{
				Status: &platformv1.Status{
					Success: false,
					Message: "Container not running",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				StopContainerFunc: func(ctx context.Context, in *platformv1.StopContainerRequest, opts ...grpc.CallOption) (*platformv1.StopContainerResponse, error) {
					if in.TimeoutSeconds != tt.timeout {
						t.Errorf("expected timeout %d, got %d", tt.timeout, in.TimeoutSeconds)
					}
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeStop(exec, "container-123", tt.timeout)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeStop() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteStop_ClientError(t *testing.T) {
	mockClient := &MockContainerClient{
		StopContainerFunc: func(ctx context.Context, in *platformv1.StopContainerRequest, opts ...grpc.CallOption) (*platformv1.StopContainerResponse, error) {
			return nil, errors.New("timeout exceeded")
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeStop(exec, "container-123", 10)

	if err == nil {
		t.Error("expected error for timeout")
	}
	if _, ok := err.(ErrContainerOperationFailed); !ok {
		t.Errorf("expected ErrContainerOperationFailed, got %T", err)
	}
}

func TestExecuteStop_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		StopContainerFunc: func(ctx context.Context, in *platformv1.StopContainerRequest, opts ...grpc.CallOption) (*platformv1.StopContainerResponse, error) {
			return &platformv1.StopContainerResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	err := executeStop(exec, "container-123", 10)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for executeRemove
func TestExecuteRemove_Success(t *testing.T) {
	tests := []struct {
		name          string
		format        cli.OutputFormat
		force         bool
		deleteVolumes bool
		resp          *platformv1.DeleteContainerResponse
		wantErr       bool
	}{
		{
			name:          "successful remove - table format",
			format:        cli.OutputFormatTable,
			force:         false,
			deleteVolumes: false,
			resp: &platformv1.DeleteContainerResponse{
				Status: &platformv1.Status{
					Success: true,
					Message: "Container removed",
				},
			},
			wantErr: false,
		},
		{
			name:          "force remove - JSON format",
			format:        cli.OutputFormatJSON,
			force:         true,
			deleteVolumes: false,
			resp: &platformv1.DeleteContainerResponse{
				Status: &platformv1.Status{
					Success: true,
				},
			},
			wantErr: false,
		},
		{
			name:          "remove with volumes - YAML format",
			format:        cli.OutputFormatYAML,
			force:         true,
			deleteVolumes: true,
			resp: &platformv1.DeleteContainerResponse{
				Status: &platformv1.Status{
					Success: true,
				},
			},
			wantErr: false,
		},
		{
			name:          "failed remove - table format",
			format:        cli.OutputFormatTable,
			force:         false,
			deleteVolumes: false,
			resp: &platformv1.DeleteContainerResponse{
				Status: &platformv1.Status{
					Success: false,
					Message: "Container is running",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				DeleteContainerFunc: func(ctx context.Context, in *platformv1.DeleteContainerRequest, opts ...grpc.CallOption) (*platformv1.DeleteContainerResponse, error) {
					if in.Force != tt.force {
						t.Errorf("expected force %v, got %v", tt.force, in.Force)
					}
					if in.DeleteVolumes != tt.deleteVolumes {
						t.Errorf("expected deleteVolumes %v, got %v", tt.deleteVolumes, in.DeleteVolumes)
					}
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeRemove(exec, "container-123", tt.force, tt.deleteVolumes)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeRemove() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteRemove_ClientError(t *testing.T) {
	mockClient := &MockContainerClient{
		DeleteContainerFunc: func(ctx context.Context, in *platformv1.DeleteContainerRequest, opts ...grpc.CallOption) (*platformv1.DeleteContainerResponse, error) {
			return nil, errors.New("permission denied")
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeRemove(exec, "protected-container", false, false)

	if err == nil {
		t.Error("expected error for protected container")
	}
	if _, ok := err.(ErrContainerOperationFailed); !ok {
		t.Errorf("expected ErrContainerOperationFailed, got %T", err)
	}
}

func TestExecuteRemove_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		DeleteContainerFunc: func(ctx context.Context, in *platformv1.DeleteContainerRequest, opts ...grpc.CallOption) (*platformv1.DeleteContainerResponse, error) {
			return &platformv1.DeleteContainerResponse{
				Status: &platformv1.Status{Success: true},
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	err := executeRemove(exec, "container-123", false, false)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for executeGet
func TestExecuteGet_Success(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		resp    *platformv1.GetContainerResponse
		wantErr bool
	}{
		{
			name:   "get container - table format",
			format: cli.OutputFormatTable,
			resp: &platformv1.GetContainerResponse{
				Container: createTestContainer("container-123", "myapp", "nginx:latest", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
			},
			wantErr: false,
		},
		{
			name:   "get container - JSON format",
			format: cli.OutputFormatJSON,
			resp: &platformv1.GetContainerResponse{
				Container: createTestContainer("container-456", "web", "httpd:latest", platformv1.ContainerState_CONTAINER_STATE_STOPPED),
			},
			wantErr: false,
		},
		{
			name:   "get container - YAML format",
			format: cli.OutputFormatYAML,
			resp: &platformv1.GetContainerResponse{
				Container: createTestContainer("container-789", "api", "api:v1", platformv1.ContainerState_CONTAINER_STATE_CREATED),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				GetContainerFunc: func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeGet(exec, "container-123")

			if (err != nil) != tt.wantErr {
				t.Errorf("executeGet() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteGet_NotFound(t *testing.T) {
	mockClient := &MockContainerClient{
		GetContainerFunc: func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
			return nil, errors.New("container not found")
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeGet(exec, "nonexistent")

	if err == nil {
		t.Error("expected error for nonexistent container")
	}
	if _, ok := err.(ErrContainerNotFound); !ok {
		t.Errorf("expected ErrContainerNotFound, got %T", err)
	}
}

func TestExecuteGet_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		GetContainerFunc: func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
			return &platformv1.GetContainerResponse{
				Container: createTestContainer("container-123", "test", "nginx", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	err := executeGet(exec, "container-123")

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for executeList
func TestExecuteList_Success(t *testing.T) {
	tests := []struct {
		name     string
		format   cli.OutputFormat
		all      bool
		pageSize int32
		filters  []string
		resp     *platformv1.ListContainersResponse
		wantErr  bool
	}{
		{
			name:     "list running containers - table format",
			format:   cli.OutputFormatTable,
			all:      false,
			pageSize: 100,
			filters:  nil,
			resp: &platformv1.ListContainersResponse{
				Containers: []*platformv1.Container{
					createTestContainer("c1", "app1", "nginx", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
					createTestContainer("c2", "app2", "redis", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
				},
			},
			wantErr: false,
		},
		{
			name:     "list all containers - JSON format",
			format:   cli.OutputFormatJSON,
			all:      true,
			pageSize: 50,
			filters:  nil,
			resp: &platformv1.ListContainersResponse{
				Containers: []*platformv1.Container{
					createTestContainer("c1", "app1", "nginx", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
					createTestContainer("c2", "app2", "redis", platformv1.ContainerState_CONTAINER_STATE_STOPPED),
					createTestContainer("c3", "app3", "postgres", platformv1.ContainerState_CONTAINER_STATE_EXITED),
				},
			},
			wantErr: false,
		},
		{
			name:     "list with filter - table format",
			format:   cli.OutputFormatTable,
			all:      true,
			pageSize: 100,
			filters:  []string{"state=stopped"},
			resp: &platformv1.ListContainersResponse{
				Containers: []*platformv1.Container{
					createTestContainer("c1", "app1", "nginx", platformv1.ContainerState_CONTAINER_STATE_STOPPED),
				},
			},
			wantErr: false,
		},
		{
			name:     "empty list - table format",
			format:   cli.OutputFormatTable,
			all:      false,
			pageSize: 100,
			filters:  nil,
			resp: &platformv1.ListContainersResponse{
				Containers: []*platformv1.Container{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				ListContainersFunc: func(ctx context.Context, in *platformv1.ListContainersRequest, opts ...grpc.CallOption) (*platformv1.ListContainersResponse, error) {
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeList(exec, tt.all, tt.pageSize, tt.filters)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeList() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteList_ClientError(t *testing.T) {
	mockClient := &MockContainerClient{
		ListContainersFunc: func(ctx context.Context, in *platformv1.ListContainersRequest, opts ...grpc.CallOption) (*platformv1.ListContainersResponse, error) {
			return nil, errors.New("database error")
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeList(exec, false, 100, nil)

	if err == nil {
		t.Error("expected error for database failure")
	}
	if _, ok := err.(ErrContainerOperationFailed); !ok {
		t.Errorf("expected ErrContainerOperationFailed, got %T", err)
	}
}

func TestExecuteList_InvalidFilter(t *testing.T) {
	mockClient := &MockContainerClient{}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeList(exec, true, 100, []string{"invalid-filter"})

	if err == nil {
		t.Error("expected error for invalid filter")
	}
	if _, ok := err.(ErrInvalidFilter); !ok {
		t.Errorf("expected ErrInvalidFilter, got %T", err)
	}
}

func TestExecuteList_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		ListContainersFunc: func(ctx context.Context, in *platformv1.ListContainersRequest, opts ...grpc.CallOption) (*platformv1.ListContainersResponse, error) {
			return &platformv1.ListContainersResponse{
				Containers: []*platformv1.Container{},
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	err := executeList(exec, false, 100, nil)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for executeAttest
func TestExecuteAttest_Success(t *testing.T) {
	tests := []struct {
		name       string
		format     cli.OutputFormat
		nonce      []byte
		pcrIndices []uint32
		resp       *platformv1.GetContainerResponse
		wantErr    bool
	}{
		{
			name:       "attest container - table format",
			format:     cli.OutputFormatTable,
			nonce:      []byte("testnonce"),
			pcrIndices: []uint32{0, 1, 14},
			resp: &platformv1.GetContainerResponse{
				Container: createTestContainer("container-123", "myapp", "nginx:latest", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
			},
			wantErr: false,
		},
		{
			name:       "attest container - JSON format",
			format:     cli.OutputFormatJSON,
			nonce:      []byte("randomnonce"),
			pcrIndices: nil,
			resp: &platformv1.GetContainerResponse{
				Container: createTestContainer("container-456", "web", "httpd:latest", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
			},
			wantErr: false,
		},
		{
			name:       "attest container - YAML format",
			format:     cli.OutputFormatYAML,
			nonce:      []byte("nonce123"),
			pcrIndices: []uint32{14},
			resp: &platformv1.GetContainerResponse{
				Container: createTestContainer("container-789", "api", "api:v1", platformv1.ContainerState_CONTAINER_STATE_STOPPED),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockContainerClient{
				GetContainerFunc: func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
					return tt.resp, nil
				},
			}

			printer := cli.NewPrinterWithWriter(tt.format, true, &bytes.Buffer{})

			exec := &ContainerCommandExecutor{
				Client:       mockClient,
				Printer:      printer,
				Ctx:          context.Background(),
				OutputFormat: tt.format,
			}

			err := executeAttest(exec, "container-123", tt.nonce, tt.pcrIndices)

			if (err != nil) != tt.wantErr {
				t.Errorf("executeAttest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecuteAttest_ContainerNotFound(t *testing.T) {
	mockClient := &MockContainerClient{
		GetContainerFunc: func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
			return nil, errors.New("container not found")
		},
	}

	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: cli.OutputFormatTable,
	}

	err := executeAttest(exec, "nonexistent", []byte("nonce"), nil)

	if err == nil {
		t.Error("expected error for nonexistent container")
	}
	if _, ok := err.(ErrContainerNotFound); !ok {
		t.Errorf("expected ErrContainerNotFound, got %T", err)
	}
}

func TestExecuteAttest_InvalidFormat(t *testing.T) {
	mockClient := &MockContainerClient{
		GetContainerFunc: func(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
			return &platformv1.GetContainerResponse{
				Container: createTestContainer("container-123", "test", "nginx", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
			}, nil
		},
	}

	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})

	exec := &ContainerCommandExecutor{
		Client:       mockClient,
		Printer:      printer,
		Ctx:          context.Background(),
		OutputFormat: "invalid",
	}

	err := executeAttest(exec, "container-123", []byte("nonce"), nil)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for print response functions with invalid formats
func TestPrintCreateResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	resp := &platformv1.CreateContainerResponse{
		Container: createTestContainer("c1", "test", "nginx", platformv1.ContainerState_CONTAINER_STATE_CREATED),
	}

	err := printCreateResponse(printer, "invalid", resp)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintStartResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	resp := &platformv1.StartContainerResponse{
		Status: &platformv1.Status{Success: true},
	}

	err := printStartResponse(printer, "invalid", resp, "test")

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintStopResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	resp := &platformv1.StopContainerResponse{
		Status: &platformv1.Status{Success: true},
	}

	err := printStopResponse(printer, "invalid", resp, "test")

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintRemoveResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	resp := &platformv1.DeleteContainerResponse{
		Status: &platformv1.Status{Success: true},
	}

	err := printRemoveResponse(printer, "invalid", resp, "test")

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintGetResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	resp := &platformv1.GetContainerResponse{
		Container: createTestContainer("c1", "test", "nginx", platformv1.ContainerState_CONTAINER_STATE_RUNNING),
	}

	err := printGetResponse(printer, "invalid", resp)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintListResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	resp := &platformv1.ListContainersResponse{
		Containers: []*platformv1.Container{},
	}

	err := printListResponse(printer, "invalid", resp)

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

func TestPrintAttestResponse_InvalidFormat(t *testing.T) {
	printer := cli.NewPrinterWithWriter("invalid", true, &bytes.Buffer{})
	result := &containerAttestationResult{
		ContainerID:   "test",
		ContainerName: "test",
		ImageID:       "nginx",
		State:         "RUNNING",
	}

	err := printAttestResponse(printer, "invalid", result, "test")

	if err == nil {
		t.Error("expected error for invalid format")
	}
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Errorf("expected ErrInvalidOutputFormat, got %T", err)
	}
}

// Tests for error types
func TestContainerErrors(t *testing.T) {
	t.Run("ErrContainerOperationFailed", func(t *testing.T) {
		err := ErrContainerOperationFailed{Operation: "create", ID: "container-123", Err: errors.New("test error")}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
		if err.Unwrap() == nil {
			t.Error("Unwrap should return inner error")
		}
	})

	t.Run("ErrContainerNotFound", func(t *testing.T) {
		err := ErrContainerNotFound{ID: "container-123"}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	})

	t.Run("ErrInvalidContainerConfig", func(t *testing.T) {
		err := ErrInvalidContainerConfig{Field: "name", Reason: "required"}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	})

	t.Run("ErrContainerClientNotInitialized", func(t *testing.T) {
		err := ErrContainerClientNotInitialized{}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	})

	t.Run("ErrAttestationFailed", func(t *testing.T) {
		err := ErrAttestationFailed{ID: "container-123", Err: errors.New("TPM error")}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
		if err.Unwrap() == nil {
			t.Error("Unwrap should return inner error")
		}
	})

	t.Run("ErrInvalidFilter", func(t *testing.T) {
		err := ErrInvalidFilter{Filter: "invalid"}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	})
}
