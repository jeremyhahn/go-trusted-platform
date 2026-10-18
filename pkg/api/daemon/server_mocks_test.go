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
	"net"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
)

// =============================================================================
// serviceRegistration - used by MockGRPCServer
// =============================================================================

// =============================================================================
// MockQUICServer - implements QUICServerInterface
// =============================================================================

// MockQUICServer is a mock implementation of QUICServerInterface for testing.
// It tracks method calls and allows configuring return errors.
type MockQUICServer struct {
	mu          sync.RWMutex
	running     atomic.Bool
	listenAddr  string
	startErr    error
	stopErr     error
	startCalled int
	stopCalled  int
	statsCalled int
	metrics     map[string]interface{}
	stats       *quic.ServerStats
}

// NewMockQUICServer creates a new MockQUICServer with the given listen address.
func NewMockQUICServer(listenAddr string) *MockQUICServer {
	return &MockQUICServer{
		listenAddr: listenAddr,
		metrics:    make(map[string]interface{}),
		stats: &quic.ServerStats{
			ActiveConnections: 0,
			TotalConnections:  0,
			ActiveStreams:     0,
			RequestsHandled:   0,
			Errors:            0,
		},
	}
}

// Start implements QUICServerInterface.Start.
func (m *MockQUICServer) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled++
	if m.startErr != nil {
		return m.startErr
	}
	m.running.Store(true)
	return nil
}

// Stop implements QUICServerInterface.Stop.
func (m *MockQUICServer) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled++
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running.Store(false)
	return nil
}

// IsRunning implements QUICServerInterface.IsRunning.
func (m *MockQUICServer) IsRunning() bool {
	return m.running.Load()
}

// ListenAddr implements QUICServerInterface.ListenAddr.
func (m *MockQUICServer) ListenAddr() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listenAddr
}

// GetMetrics implements QUICServerInterface.GetMetrics.
func (m *MockQUICServer) GetMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]interface{})
	for k, v := range m.metrics {
		result[k] = v
	}
	// Add standard metrics
	result["running"] = m.running.Load()
	result["active_connections"] = m.stats.ActiveConnections
	result["total_connections"] = m.stats.TotalConnections
	result["active_streams"] = m.stats.ActiveStreams
	result["total_requests"] = m.stats.RequestsHandled
	result["total_errors"] = m.stats.Errors
	return result
}

// Stats implements QUICServerInterface.Stats.
func (m *MockQUICServer) Stats() *quic.ServerStats {
	m.mu.Lock()
	m.statsCalled++
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// SetStartError configures the error to return from Start.
func (m *MockQUICServer) SetStartError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startErr = err
}

// SetStopError configures the error to return from Stop.
func (m *MockQUICServer) SetStopError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopErr = err
}

// SetListenAddr updates the listen address.
func (m *MockQUICServer) SetListenAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listenAddr = addr
}

// SetMetric sets a metric value for testing.
func (m *MockQUICServer) SetMetric(key string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metrics[key] = value
}

// SetStats sets the server stats for testing.
func (m *MockQUICServer) SetStats(stats *quic.ServerStats) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats = stats
}

// GetStartCalled returns the number of times Start was called.
func (m *MockQUICServer) GetStartCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.startCalled
}

// GetStopCalled returns the number of times Stop was called.
func (m *MockQUICServer) GetStopCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopCalled
}

// GetStatsCalled returns the number of times Stats was called.
func (m *MockQUICServer) GetStatsCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.statsCalled
}

// Reset clears all call counts and errors.
func (m *MockQUICServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = 0
	m.stopCalled = 0
	m.statsCalled = 0
	m.startErr = nil
	m.stopErr = nil
	m.running.Store(false)
	m.metrics = make(map[string]interface{})
	m.stats = &quic.ServerStats{}
}

// =============================================================================
// MockRESTServer - implements RESTServerInterface
// =============================================================================

// MockRESTServer is a mock implementation of RESTServerInterface for testing.
// It tracks method calls and allows configuring return errors.
type MockRESTServer struct {
	mu              sync.RWMutex
	running         atomic.Bool
	startErr        error
	stopErr         error
	forceStopErr    error
	startCalled     int
	stopCalled      int
	forceStopCalled int
	listenAddr      string
}

// NewMockRESTServer creates a new MockRESTServer.
func NewMockRESTServer() *MockRESTServer {
	return &MockRESTServer{
		listenAddr: "127.0.0.1:8443",
	}
}

// Start implements RESTServerInterface.Start.
func (m *MockRESTServer) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled++
	if m.startErr != nil {
		return m.startErr
	}
	m.running.Store(true)
	return nil
}

// Stop implements RESTServerInterface.Stop.
func (m *MockRESTServer) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled++
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running.Store(false)
	return nil
}

// ForceStop implements RESTServerInterface.ForceStop.
func (m *MockRESTServer) ForceStop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forceStopCalled++
	if m.forceStopErr != nil {
		return m.forceStopErr
	}
	m.running.Store(false)
	return nil
}

// IsRunning implements RESTServerInterface.IsRunning.
func (m *MockRESTServer) IsRunning() bool {
	return m.running.Load()
}

// SetStartError configures the error to return from Start.
func (m *MockRESTServer) SetStartError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startErr = err
}

// SetStopError configures the error to return from Stop.
func (m *MockRESTServer) SetStopError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopErr = err
}

// SetForceStopError configures the error to return from ForceStop.
func (m *MockRESTServer) SetForceStopError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.forceStopErr = err
}

// SetListenAddr sets the listen address for testing.
func (m *MockRESTServer) SetListenAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listenAddr = addr
}

// GetListenAddr returns the configured listen address.
func (m *MockRESTServer) GetListenAddr() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listenAddr
}

// GetStartCalled returns the number of times Start was called.
func (m *MockRESTServer) GetStartCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.startCalled
}

// GetStopCalled returns the number of times Stop was called.
func (m *MockRESTServer) GetStopCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopCalled
}

// GetForceStopCalled returns the number of times ForceStop was called.
func (m *MockRESTServer) GetForceStopCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.forceStopCalled
}

// Reset clears all call counts and errors.
func (m *MockRESTServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = 0
	m.stopCalled = 0
	m.forceStopCalled = 0
	m.startErr = nil
	m.stopErr = nil
	m.forceStopErr = nil
	m.running.Store(false)
}

// =============================================================================
// MockMCPServer - implements MCPServerInterface
// =============================================================================

// MockMCPServer is a mock implementation of MCPServerInterface for testing.
// It tracks method calls and allows configuring return errors.
type MockMCPServer struct {
	mu          sync.RWMutex
	running     atomic.Bool
	startErr    error
	stopErr     error
	startCalled int
	stopCalled  int
	transport   string
	httpAddr    string
}

// NewMockMCPServer creates a new MockMCPServer.
func NewMockMCPServer() *MockMCPServer {
	return &MockMCPServer{
		transport: "http",
		httpAddr:  "127.0.0.1:9445",
	}
}

// Start implements MCPServerInterface.Start.
func (m *MockMCPServer) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled++
	if m.startErr != nil {
		return m.startErr
	}
	m.running.Store(true)
	return nil
}

// Stop implements MCPServerInterface.Stop.
func (m *MockMCPServer) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled++
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running.Store(false)
	return nil
}

// IsRunning implements MCPServerInterface.IsRunning.
func (m *MockMCPServer) IsRunning() bool {
	return m.running.Load()
}

// SetStartError configures the error to return from Start.
func (m *MockMCPServer) SetStartError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startErr = err
}

// SetStopError configures the error to return from Stop.
func (m *MockMCPServer) SetStopError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopErr = err
}

// SetTransport sets the transport type for testing.
func (m *MockMCPServer) SetTransport(transport string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transport = transport
}

// GetTransport returns the configured transport.
func (m *MockMCPServer) GetTransport() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.transport
}

// SetHTTPAddr sets the HTTP address for testing.
func (m *MockMCPServer) SetHTTPAddr(addr string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpAddr = addr
}

// GetHTTPAddr returns the configured HTTP address.
func (m *MockMCPServer) GetHTTPAddr() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.httpAddr
}

// GetStartCalled returns the number of times Start was called.
func (m *MockMCPServer) GetStartCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.startCalled
}

// GetStopCalled returns the number of times Stop was called.
func (m *MockMCPServer) GetStopCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopCalled
}

// Reset clears all call counts and errors.
func (m *MockMCPServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = 0
	m.stopCalled = 0
	m.startErr = nil
	m.stopErr = nil
	m.running.Store(false)
}

// =============================================================================
// MockGRPCServer - implements GRPCServerInterface
// =============================================================================

// MockGRPCServer is a mock implementation of GRPCServerInterface for testing.
// It tracks method calls and allows configuring return errors.
type MockGRPCServer struct {
	mu                    sync.RWMutex
	serveCalled           int
	gracefulStopCalled    int
	stopCalled            int
	registerServiceCalled int
	serveErr              error
	listener              net.Listener
}

// NewMockGRPCServer creates a new MockGRPCServer.
func NewMockGRPCServer() *MockGRPCServer {
	return &MockGRPCServer{}
}

// RegisterService implements GRPCServerInterface.RegisterService.
func (m *MockGRPCServer) RegisterService(_ *grpc.ServiceDesc, _ interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.registerServiceCalled++
}

// Serve implements GRPCServerInterface.Serve.
func (m *MockGRPCServer) Serve(lis net.Listener) error {
	m.mu.Lock()
	m.serveCalled++
	m.listener = lis
	serveErr := m.serveErr
	m.mu.Unlock()
	if serveErr != nil {
		return serveErr
	}
	// In a mock, we don't actually block on serving
	return nil
}

// GracefulStop implements GRPCServerInterface.GracefulStop.
func (m *MockGRPCServer) GracefulStop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gracefulStopCalled++
}

// Stop implements GRPCServerInterface.Stop.
func (m *MockGRPCServer) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled++
}

// SetServeError configures the error to return from Serve.
func (m *MockGRPCServer) SetServeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serveErr = err
}

// GetServeCalled returns the number of times Serve was called.
func (m *MockGRPCServer) GetServeCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.serveCalled
}

// GetGracefulStopCalled returns the number of times GracefulStop was called.
func (m *MockGRPCServer) GetGracefulStopCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.gracefulStopCalled
}

// GetStopCalled returns the number of times Stop was called.
func (m *MockGRPCServer) GetStopCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stopCalled
}

// GetRegisterServiceCalled returns the number of times RegisterService was called.
func (m *MockGRPCServer) GetRegisterServiceCalled() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registerServiceCalled
}

// GetListener returns the listener passed to Serve.
func (m *MockGRPCServer) GetListener() net.Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.listener
}

// Reset clears all call counts and errors.
func (m *MockGRPCServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.serveCalled = 0
	m.gracefulStopCalled = 0
	m.stopCalled = 0
	m.registerServiceCalled = 0
	m.serveErr = nil
	m.listener = nil
}

// =============================================================================
// Compile-time interface verification
// =============================================================================

var (
	_ QUICServerInterface = (*MockQUICServer)(nil)
	_ RESTServerInterface = (*MockRESTServer)(nil)
	_ MCPServerInterface  = (*MockMCPServer)(nil)
	_ GRPCServerInterface = (*MockGRPCServer)(nil)
)
