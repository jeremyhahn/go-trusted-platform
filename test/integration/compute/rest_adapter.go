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

//go:build integration

package compute_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// computeVMsPath is the daemon REST route serving the VM collection.
const computeVMsPath = "/api/v1/compute/vms"

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTRequestFailed indicates a REST API request failure.
type ErrRESTRequestFailed struct {
	Operation  string
	StatusCode int
	Message    string
	Body       string
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("compute: REST error [%s]: %s (status: %d, body: %s)",
		e.Operation, e.Message, e.StatusCode, e.Body)
}

// ErrRESTSetupFailed indicates the REST endpoint is unreachable.
type ErrRESTSetupFailed struct {
	Endpoint string
	Message  string
}

func (e ErrRESTSetupFailed) Error() string {
	return fmt.Sprintf("compute: REST setup failed for %s: %s", e.Endpoint, e.Message)
}

// =============================================================================
// REST Adapter
// =============================================================================

// RESTAdapter implements ComputeCommands using the REST API. It drives the
// Go SDK compute client, whose requests travel as protobuf JSON over the
// daemon's REST routes, so REST is held to the same contract as gRPC.
type RESTAdapter struct {
	endpoint   string
	httpClient *http.Client
	client     *computesvc.Client
}

// NewRESTAdapter creates a new REST adapter.
func NewRESTAdapter() *RESTAdapter {
	adapter := &RESTAdapter{
		endpoint: GetRESTEndpoint(),
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
	}
	adapter.client = computesvc.NewClientFromGRPC(&restComputeClient{adapter: adapter})
	return adapter
}

// Setup verifies the REST endpoint is reachable.
func (a *RESTAdapter) Setup(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+"/health", nil)
	if err != nil {
		return ErrRESTSetupFailed{
			Endpoint: a.endpoint,
			Message:  "failed to create request: " + err.Error(),
		}
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return ErrRESTSetupFailed{
			Endpoint: a.endpoint,
			Message:  "endpoint not reachable: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	return nil
}

// Teardown cleans up after testing.
func (a *RESTAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name.
func (a *RESTAdapter) Name() string {
	return "REST"
}

// call sends in as protobuf JSON (when non-nil) with query appended to the
// route, and decodes a 2xx reply into out with protojson.
func (a *RESTAdapter) call(ctx context.Context, method, path string, query url.Values, in, out proto.Message) error {
	operation := method + " " + path
	var bodyReader io.Reader
	if in != nil {
		data, err := protojson.Marshal(in)
		if err != nil {
			return ErrRESTRequestFailed{Operation: operation, Message: "failed to marshal request: " + err.Error()}
		}
		bodyReader = bytes.NewReader(data)
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, a.endpoint+path, bodyReader)
	if err != nil {
		return ErrRESTRequestFailed{Operation: operation, Message: "failed to create request: " + err.Error()}
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return ErrRESTRequestFailed{Operation: operation, Message: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: resp.StatusCode,
			Message:    "failed to read response: " + err.Error(),
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: resp.StatusCode,
			Message:    "unexpected status code",
			Body:       string(respBody),
		}
	}

	if err := protojson.Unmarshal(respBody, out); err != nil {
		return ErrRESTRequestFailed{
			Operation:  operation,
			StatusCode: resp.StatusCode,
			Message:    "failed to parse response: " + err.Error(),
			Body:       string(respBody),
		}
	}

	return nil
}

// restRPC runs one compute RPC over REST and returns its decoded reply.
func restRPC[Resp any, PResp interface {
	*Resp
	proto.Message
}](ctx context.Context, a *RESTAdapter, method, path string, query url.Values, in proto.Message) (PResp, error) {
	out := PResp(new(Resp))
	if err := a.call(ctx, method, path, query, in, out); err != nil {
		return nil, err
	}
	return out, nil
}

// vmPath is the REST route of one VM, or of an action on it when action is
// non-empty.
func vmPath(id, action string) string {
	path := computeVMsPath + "/" + url.PathEscape(id)
	if action != "" {
		path += "/" + action
	}
	return path
}

// listVMsQuery names each set ListVMsRequest field as the query parameter
// the daemon decodes into it.
func listVMsQuery(in *pb.ListVMsRequest) url.Values {
	query := url.Values{}
	for _, state := range in.GetStates() {
		query.Add("states", state.String())
	}
	if page := in.GetPagination().GetPage(); page > 0 {
		query.Set("pagination.page", strconv.FormatUint(uint64(page), 10))
	}
	if pageSize := in.GetPagination().GetPageSize(); pageSize > 0 {
		query.Set("pagination.pageSize", strconv.FormatUint(uint64(pageSize), 10))
	}
	for key, value := range in.GetSelector().GetMatchLabels() {
		query.Set("selector.matchLabels."+key, value)
	}
	return query
}

// restComputeClient carries the Go SDK compute client's VM RPCs over the
// daemon REST surface: each sends the SDK's own request message to the route
// that serves its RPC. ComputeCommands drives only the six VM RPCs below; the
// embedded interface is nil and never reached.
type restComputeClient struct {
	pb.ComputeServiceClient

	adapter *RESTAdapter
}

func (c *restComputeClient) CreateVM(ctx context.Context, in *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.CreateVMResponse, error) {
	return restRPC[pb.CreateVMResponse](ctx, c.adapter, http.MethodPost, computeVMsPath, nil, in)
}

func (c *restComputeClient) StartVM(ctx context.Context, in *pb.StartVMRequest, _ ...grpc.CallOption) (*pb.StartVMResponse, error) {
	return restRPC[pb.StartVMResponse](ctx, c.adapter, http.MethodPost, vmPath(in.GetId(), "start"), nil, in)
}

func (c *restComputeClient) StopVM(ctx context.Context, in *pb.StopVMRequest, _ ...grpc.CallOption) (*pb.StopVMResponse, error) {
	return restRPC[pb.StopVMResponse](ctx, c.adapter, http.MethodPost, vmPath(in.GetId(), "stop"), nil, in)
}

func (c *restComputeClient) DeleteVM(ctx context.Context, in *pb.DeleteVMRequest, _ ...grpc.CallOption) (*pb.DeleteVMResponse, error) {
	return restRPC[pb.DeleteVMResponse](ctx, c.adapter, http.MethodDelete, vmPath(in.GetId(), ""), nil, in)
}

func (c *restComputeClient) GetVM(ctx context.Context, in *pb.GetVMRequest, _ ...grpc.CallOption) (*pb.GetVMResponse, error) {
	return restRPC[pb.GetVMResponse](ctx, c.adapter, http.MethodGet, vmPath(in.GetId(), ""), nil, nil)
}

func (c *restComputeClient) ListVMs(ctx context.Context, in *pb.ListVMsRequest, _ ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	return restRPC[pb.ListVMsResponse](ctx, c.adapter, http.MethodGet, computeVMsPath, listVMsQuery(in), nil)
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via REST.
func (a *RESTAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	vm, err := a.client.CreateVMDomain(ctx, createVMParamsFromOptions(opts))
	if err != nil {
		return nil, err
	}
	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine via REST.
func (a *RESTAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.client.StartVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, err
	}

	result := &StartVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// StopVM stops a virtual machine via REST.
func (a *RESTAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	status, err := a.client.StopVMDomain(ctx, &computesvc.StopVMParams{
		ID:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	})
	if err != nil {
		return nil, err
	}

	result := &StopVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// DeleteVM deletes a virtual machine via REST.
func (a *RESTAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	status, err := a.client.DeleteVMDomain(ctx, &computesvc.DeleteVMParams{
		ID:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	})
	if err != nil {
		return nil, err
	}

	result := &DeleteVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// GetVM retrieves a virtual machine via REST.
func (a *RESTAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm, err := a.client.GetVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, err
	}
	if vm == nil {
		return nil, ErrVMNotFound(opts)
	}
	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines via REST.
func (a *RESTAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	domainResult, err := a.client.ListVMsDomain(ctx, listVMsParamsFromOptions(opts))
	if err != nil {
		return nil, err
	}
	return listVMsResultFromDomain(domainResult), nil
}
