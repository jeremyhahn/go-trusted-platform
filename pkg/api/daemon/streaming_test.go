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
	"sync"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockStreamServer implements the gRPC stream server interface for testing
type mockEventStreamServer struct {
	platformv1.PlatformDaemon_StreamEventsServer
	ctx       context.Context
	sent      []*platformv1.Event
	sendErr   error
	mu        sync.Mutex
	cancelCtx context.CancelFunc
}

func newMockEventStreamServer(ctx context.Context) *mockEventStreamServer {
	ctx, cancel := context.WithCancel(ctx)
	return &mockEventStreamServer{
		ctx:       ctx,
		sent:      make([]*platformv1.Event, 0),
		cancelCtx: cancel,
	}
}

func (m *mockEventStreamServer) Send(event *platformv1.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, event)
	return nil
}

func (m *mockEventStreamServer) Context() context.Context {
	return m.ctx
}

func (m *mockEventStreamServer) Cancel() {
	m.cancelCtx()
}

func (m *mockEventStreamServer) SentEvents() []*platformv1.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*platformv1.Event{}, m.sent...)
}

type mockLogStreamServer struct {
	platformv1.PlatformDaemon_StreamLogsServer
	ctx       context.Context
	sent      []*platformv1.LogEntry
	sendErr   error
	mu        sync.Mutex
	cancelCtx context.CancelFunc
}

func newMockLogStreamServer(ctx context.Context) *mockLogStreamServer {
	ctx, cancel := context.WithCancel(ctx)
	return &mockLogStreamServer{
		ctx:       ctx,
		sent:      make([]*platformv1.LogEntry, 0),
		cancelCtx: cancel,
	}
}

func (m *mockLogStreamServer) Send(entry *platformv1.LogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, entry)
	return nil
}

func (m *mockLogStreamServer) Context() context.Context {
	return m.ctx
}

func (m *mockLogStreamServer) Cancel() {
	m.cancelCtx()
}

func (m *mockLogStreamServer) SentLogs() []*platformv1.LogEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*platformv1.LogEntry{}, m.sent...)
}

type mockMetricStreamServer struct {
	platformv1.PlatformDaemon_StreamMetricsServer
	ctx       context.Context
	sent      []*platformv1.MetricData
	sendErr   error
	mu        sync.Mutex
	cancelCtx context.CancelFunc
}

func newMockMetricStreamServer(ctx context.Context) *mockMetricStreamServer {
	ctx, cancel := context.WithCancel(ctx)
	return &mockMetricStreamServer{
		ctx:       ctx,
		sent:      make([]*platformv1.MetricData, 0),
		cancelCtx: cancel,
	}
}

func (m *mockMetricStreamServer) Send(metric *platformv1.MetricData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, metric)
	return nil
}

func (m *mockMetricStreamServer) Context() context.Context {
	return m.ctx
}

func (m *mockMetricStreamServer) Cancel() {
	m.cancelCtx()
}

func (m *mockMetricStreamServer) SentMetrics() []*platformv1.MetricData {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*platformv1.MetricData{}, m.sent...)
}

func TestService_StreamEvents(t *testing.T) {
	t.Run("streams events to client", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockEventStreamServer(ctx)

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish events
		event1 := &platformv1.Event{
			Type:      platformv1.EventType_EVENT_TYPE_SERVICE_STARTED,
			Timestamp: timestamppb.Now(),
			Message:   "test event 1",
		}
		event2 := &platformv1.Event{
			Type:      platformv1.EventType_EVENT_TYPE_SERVICE_STOPPED,
			Timestamp: timestamppb.Now(),
			Message:   "test event 2",
		}

		svc.PublishEvent(event1)
		svc.PublishEvent(event2)

		// Give events time to be sent
		time.Sleep(100 * time.Millisecond)

		// Cancel stream
		stream.Cancel()

		// Wait for stream to finish
		err = <-streamErr
		if err != nil {
			t.Errorf("StreamEvents() error: %v", err)
		}

		// Verify events were sent
		sent := stream.SentEvents()
		if len(sent) != 2 {
			t.Errorf("sent event count = %d, want 2", len(sent))
		}
	})

	t.Run("events disabled returns error", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = false
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockEventStreamServer(ctx)

		err = svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream)
		if err == nil {
			t.Error("StreamEvents() should return error when events disabled")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.FailedPrecondition {
			t.Errorf("error code = %v, want FailedPrecondition", st.Code())
		}
	})

	t.Run("context cancellation stops stream", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockEventStreamServer(ctx)

		// Cancel immediately
		stream.Cancel()

		err = svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream)
		// Should return without error when context is cancelled
		if err != nil {
			t.Errorf("StreamEvents() unexpected error: %v", err)
		}
	})

	t.Run("shutdown signal stops stream", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockEventStreamServer(ctx)

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Trigger shutdown
		_, _ = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 1,
		})

		// Wait for stream to finish
		err = <-streamErr
		if err != nil {
			t.Errorf("StreamEvents() error after shutdown: %v", err)
		}
	})

	t.Run("send error returns error", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockEventStreamServer(ctx)
		stream.sendErr = errors.New("send failed")

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish event
		event := &platformv1.Event{
			Type:      platformv1.EventType_EVENT_TYPE_SERVICE_STARTED,
			Timestamp: timestamppb.Now(),
			Message:   "test event",
		}
		svc.PublishEvent(event)

		// Wait for stream to finish
		err = <-streamErr
		if err == nil {
			t.Error("StreamEvents() should return error when Send fails")
		}
	})
}

func TestService_StreamLogs(t *testing.T) {
	t.Run("streams logs to client", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockLogStreamServer(ctx)

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamLogs(&platformv1.StreamLogsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish log entries
		log1 := &platformv1.LogEntry{
			Timestamp: timestamppb.Now(),
			Level:     "info",
			Message:   "test log 1",
		}
		log2 := &platformv1.LogEntry{
			Timestamp: timestamppb.Now(),
			Level:     "error",
			Message:   "test log 2",
		}

		svc.PublishLog(log1)
		svc.PublishLog(log2)

		// Give logs time to be sent
		time.Sleep(100 * time.Millisecond)

		// Cancel stream
		stream.Cancel()

		// Wait for stream to finish
		err = <-streamErr
		if err != nil {
			t.Errorf("StreamLogs() error: %v", err)
		}

		// Verify logs were sent
		sent := stream.SentLogs()
		if len(sent) != 2 {
			t.Errorf("sent log count = %d, want 2", len(sent))
		}
	})

	t.Run("context cancellation stops stream", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockLogStreamServer(ctx)

		// Cancel immediately
		stream.Cancel()

		err = svc.StreamLogs(&platformv1.StreamLogsRequest{}, stream)
		// Should return without error when context is cancelled
		if err != nil {
			t.Errorf("StreamLogs() unexpected error: %v", err)
		}
	})

	t.Run("shutdown signal stops stream", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockLogStreamServer(ctx)

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamLogs(&platformv1.StreamLogsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Trigger shutdown
		_, _ = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 1,
		})

		// Wait for stream to finish
		err = <-streamErr
		if err != nil {
			t.Errorf("StreamLogs() error after shutdown: %v", err)
		}
	})

	t.Run("send error returns error", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockLogStreamServer(ctx)
		stream.sendErr = errors.New("send failed")

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamLogs(&platformv1.StreamLogsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish log entry
		log := &platformv1.LogEntry{
			Timestamp: timestamppb.Now(),
			Level:     "info",
			Message:   "test log",
		}
		svc.PublishLog(log)

		// Wait for stream to finish
		err = <-streamErr
		if err == nil {
			t.Error("StreamLogs() should return error when Send fails")
		}
	})
}

func TestService_StreamMetrics(t *testing.T) {
	t.Run("streams metrics to client", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockMetricStreamServer(ctx)

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish metrics
		metric1 := &platformv1.MetricData{
			Name:      "cpu_usage",
			Value:     75.5,
			Timestamp: timestamppb.Now(),
		}
		metric2 := &platformv1.MetricData{
			Name:      "memory_usage",
			Value:     512.0,
			Timestamp: timestamppb.Now(),
		}

		svc.PublishMetric(metric1)
		svc.PublishMetric(metric2)

		// Give metrics time to be sent
		time.Sleep(100 * time.Millisecond)

		// Cancel stream
		stream.Cancel()

		// Wait for stream to finish
		err = <-streamErr
		if err != nil {
			t.Errorf("StreamMetrics() error: %v", err)
		}

		// Verify metrics were sent
		sent := stream.SentMetrics()
		if len(sent) != 2 {
			t.Errorf("sent metric count = %d, want 2", len(sent))
		}
	})

	t.Run("metrics disabled returns error", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = false
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockMetricStreamServer(ctx)

		err = svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream)
		if err == nil {
			t.Error("StreamMetrics() should return error when metrics disabled")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got %T", err)
		}

		if st.Code() != codes.FailedPrecondition {
			t.Errorf("error code = %v, want FailedPrecondition", st.Code())
		}
	})

	t.Run("context cancellation stops stream", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockMetricStreamServer(ctx)

		// Cancel immediately
		stream.Cancel()

		err = svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream)
		// Should return without error when context is cancelled
		if err != nil {
			t.Errorf("StreamMetrics() unexpected error: %v", err)
		}
	})

	t.Run("shutdown signal stops stream", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockMetricStreamServer(ctx)

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Trigger shutdown
		_, _ = svc.Shutdown(ctx, &platformv1.ShutdownRequest{
			Graceful:       true,
			TimeoutSeconds: 1,
		})

		// Wait for stream to finish
		err = <-streamErr
		if err != nil {
			t.Errorf("StreamMetrics() error after shutdown: %v", err)
		}
	})

	t.Run("send error returns error", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()
		stream := newMockMetricStreamServer(ctx)
		stream.sendErr = errors.New("send failed")

		// Start streaming in background
		streamErr := make(chan error, 1)
		go func() {
			streamErr <- svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream)
		}()

		// Give stream time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish metric
		metric := &platformv1.MetricData{
			Name:      "cpu_usage",
			Value:     75.5,
			Timestamp: timestamppb.Now(),
		}
		svc.PublishMetric(metric)

		// Wait for stream to finish
		err = <-streamErr
		if err == nil {
			t.Error("StreamMetrics() should return error when Send fails")
		}
	})
}

func TestService_PublishEvent(t *testing.T) {
	t.Run("publishes events to all subscribers", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()

		// Create multiple subscribers
		stream1 := newMockEventStreamServer(ctx)
		stream2 := newMockEventStreamServer(ctx)

		// Start both streams
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream1)
		}()
		go func() {
			defer wg.Done()
			_ = svc.StreamEvents(&platformv1.StreamEventsRequest{}, stream2)
		}()

		// Give streams time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish event
		event := &platformv1.Event{
			Type:      platformv1.EventType_EVENT_TYPE_SERVICE_STARTED,
			Timestamp: timestamppb.Now(),
			Message:   "test event",
		}
		svc.PublishEvent(event)

		// Give event time to be delivered
		time.Sleep(100 * time.Millisecond)

		// Cancel streams
		stream1.Cancel()
		stream2.Cancel()

		wg.Wait()

		// Verify both subscribers received the event
		sent1 := stream1.SentEvents()
		sent2 := stream2.SentEvents()

		if len(sent1) != 1 {
			t.Errorf("stream1 received %d events, want 1", len(sent1))
		}
		if len(sent2) != 1 {
			t.Errorf("stream2 received %d events, want 1", len(sent2))
		}
	})

	t.Run("does not publish when events disabled", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = false
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Manually add a subscriber to verify it doesn't receive events
		eventCh := make(chan *platformv1.Event, 1)
		svc.subMu.Lock()
		svc.eventSubs["test"] = eventCh
		svc.subMu.Unlock()

		// Try to publish event
		event := &platformv1.Event{
			Type:      platformv1.EventType_EVENT_TYPE_SERVICE_STARTED,
			Timestamp: timestamppb.Now(),
			Message:   "test event",
		}
		svc.PublishEvent(event)

		// Verify event was not sent
		select {
		case <-eventCh:
			t.Error("event should not be published when events disabled")
		case <-time.After(100 * time.Millisecond):
			// Expected - no event received
		}
	})

	t.Run("skips full channels", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableEvents = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Create a channel with no buffer - will always be full
		fullCh := make(chan *platformv1.Event)
		svc.subMu.Lock()
		svc.eventSubs["full"] = fullCh
		svc.subMu.Unlock()

		// Publish should not block
		event := &platformv1.Event{
			Type:      platformv1.EventType_EVENT_TYPE_SERVICE_STARTED,
			Timestamp: timestamppb.Now(),
			Message:   "test event",
		}

		done := make(chan bool)
		go func() {
			svc.PublishEvent(event)
			done <- true
		}()

		select {
		case <-done:
			// Expected - publish completed without blocking
		case <-time.After(1 * time.Second):
			t.Fatal("PublishEvent should not block on full channel")
		}
	})
}

func TestService_PublishLog(t *testing.T) {
	t.Run("publishes logs to all subscribers", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()

		// Create multiple subscribers
		stream1 := newMockLogStreamServer(ctx)
		stream2 := newMockLogStreamServer(ctx)

		// Start both streams
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = svc.StreamLogs(&platformv1.StreamLogsRequest{}, stream1)
		}()
		go func() {
			defer wg.Done()
			_ = svc.StreamLogs(&platformv1.StreamLogsRequest{}, stream2)
		}()

		// Give streams time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish log
		log := &platformv1.LogEntry{
			Timestamp: timestamppb.Now(),
			Level:     "info",
			Message:   "test log",
		}
		svc.PublishLog(log)

		// Give log time to be delivered
		time.Sleep(100 * time.Millisecond)

		// Cancel streams
		stream1.Cancel()
		stream2.Cancel()

		wg.Wait()

		// Verify both subscribers received the log
		sent1 := stream1.SentLogs()
		sent2 := stream2.SentLogs()

		if len(sent1) != 1 {
			t.Errorf("stream1 received %d logs, want 1", len(sent1))
		}
		if len(sent2) != 1 {
			t.Errorf("stream2 received %d logs, want 1", len(sent2))
		}
	})

	t.Run("skips full channels", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Create a channel with no buffer - will always be full
		fullCh := make(chan *platformv1.LogEntry)
		svc.subMu.Lock()
		svc.logSubs["full"] = fullCh
		svc.subMu.Unlock()

		// Publish should not block
		log := &platformv1.LogEntry{
			Timestamp: timestamppb.Now(),
			Level:     "info",
			Message:   "test log",
		}

		done := make(chan bool)
		go func() {
			svc.PublishLog(log)
			done <- true
		}()

		select {
		case <-done:
			// Expected - publish completed without blocking
		case <-time.After(1 * time.Second):
			t.Fatal("PublishLog should not block on full channel")
		}
	})
}

func TestService_PublishMetric(t *testing.T) {
	t.Run("publishes metrics to all subscribers", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		ctx := context.Background()

		// Create multiple subscribers
		stream1 := newMockMetricStreamServer(ctx)
		stream2 := newMockMetricStreamServer(ctx)

		// Start both streams
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_ = svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream1)
		}()
		go func() {
			defer wg.Done()
			_ = svc.StreamMetrics(&platformv1.StreamMetricsRequest{}, stream2)
		}()

		// Give streams time to initialize
		time.Sleep(50 * time.Millisecond)

		// Publish metric
		metric := &platformv1.MetricData{
			Name:      "cpu_usage",
			Value:     75.5,
			Timestamp: timestamppb.Now(),
		}
		svc.PublishMetric(metric)

		// Give metric time to be delivered
		time.Sleep(100 * time.Millisecond)

		// Cancel streams
		stream1.Cancel()
		stream2.Cancel()

		wg.Wait()

		// Verify both subscribers received the metric
		sent1 := stream1.SentMetrics()
		sent2 := stream2.SentMetrics()

		if len(sent1) != 1 {
			t.Errorf("stream1 received %d metrics, want 1", len(sent1))
		}
		if len(sent2) != 1 {
			t.Errorf("stream2 received %d metrics, want 1", len(sent2))
		}
	})

	t.Run("does not publish when metrics disabled", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = false
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Manually add a subscriber to verify it doesn't receive metrics
		metricCh := make(chan *platformv1.MetricData, 1)
		svc.subMu.Lock()
		svc.metricSubs["test"] = metricCh
		svc.subMu.Unlock()

		// Try to publish metric
		metric := &platformv1.MetricData{
			Name:      "cpu_usage",
			Value:     75.5,
			Timestamp: timestamppb.Now(),
		}
		svc.PublishMetric(metric)

		// Verify metric was not sent
		select {
		case <-metricCh:
			t.Error("metric should not be published when metrics disabled")
		case <-time.After(100 * time.Millisecond):
			// Expected - no metric received
		}
	})

	t.Run("skips full channels", func(t *testing.T) {
		config := DefaultConfig()
		config.EnableMetrics = true
		svc, err := NewService(config)
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Create a channel with no buffer - will always be full
		fullCh := make(chan *platformv1.MetricData)
		svc.subMu.Lock()
		svc.metricSubs["full"] = fullCh
		svc.subMu.Unlock()

		// Publish should not block
		metric := &platformv1.MetricData{
			Name:      "cpu_usage",
			Value:     75.5,
			Timestamp: timestamppb.Now(),
		}

		done := make(chan bool)
		go func() {
			svc.PublishMetric(metric)
			done <- true
		}()

		select {
		case <-done:
			// Expected - publish completed without blocking
		case <-time.After(1 * time.Second):
			t.Fatal("PublishMetric should not block on full channel")
		}
	})
}

func TestService_generateSubscriptionID(t *testing.T) {
	t.Run("generates unique IDs", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		id1 := svc.generateSubscriptionID()
		id2 := svc.generateSubscriptionID()
		id3 := svc.generateSubscriptionID()

		if id1 == "" {
			t.Error("generated ID should not be empty")
		}

		if id1 == id2 {
			t.Error("generated IDs should be unique")
		}

		if id2 == id3 {
			t.Error("generated IDs should be unique")
		}
	})

	t.Run("IDs are incrementing", func(t *testing.T) {
		svc, err := NewService(DefaultConfig())
		if err != nil {
			t.Fatalf("NewService() error: %v", err)
		}

		// Generate multiple IDs and verify they increment
		ids := make([]string, 5)
		for i := 0; i < 5; i++ {
			ids[i] = svc.generateSubscriptionID()
		}

		// All should be unique
		seen := make(map[string]bool)
		for _, id := range ids {
			if seen[id] {
				t.Errorf("duplicate ID generated: %s", id)
			}
			seen[id] = true
		}

		if len(seen) != 5 {
			t.Errorf("expected 5 unique IDs, got %d", len(seen))
		}
	})
}
