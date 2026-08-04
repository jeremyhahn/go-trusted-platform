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

package metrics

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Collector manages metrics collection and HTTP server
type Collector struct {
	config           *Config
	metrics          *Metrics
	server           *http.Server
	running          atomic.Bool
	startTime        time.Time
	mu               sync.RWMutex
	stopChan         chan struct{}
	stoppedChan      chan struct{}
	collectionActive bool
}

// NewCollector creates a new metrics collector
func NewCollector(config *Config) (*Collector, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	if !config.Enabled {
		return nil, ErrMetricsNotEnabled{}
	}

	metrics, err := New(config)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create metrics", Err: err}
	}

	collector := &Collector{
		config:      config,
		metrics:     metrics,
		startTime:   time.Now(),
		stopChan:    make(chan struct{}),
		stoppedChan: make(chan struct{}),
	}

	return collector, nil
}

// Start starts the metrics collector and HTTP server
func (c *Collector) Start(ctx context.Context) error {
	if c.running.Swap(true) {
		return &MessageError{Msg: "metrics collector already running"}
	}

	// Set start time metric
	c.metrics.DaemonStartTime.Set(float64(c.startTime.Unix()))

	// Create HTTP server for metrics endpoint
	mux := http.NewServeMux()
	mux.Handle(c.config.Path, promhttp.Handler())

	// Add health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	c.server = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start HTTP server in goroutine
	go func() {
		if err := c.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't crash
			fmt.Printf("metrics server error: %v\n", err)
		}
	}()

	// Start background collection goroutine
	if c.config.EnableRuntimeMetrics || c.config.EnableProcessMetrics {
		c.collectionActive = true
		go c.collectLoop()
	} else {
		// If collection is not active, immediately close the stopped channel
		close(c.stoppedChan)
	}

	return nil
}

// Stop gracefully stops the metrics collector
func (c *Collector) Stop(ctx context.Context) error {
	if !c.running.Load() {
		return &MessageError{Msg: "metrics collector not running"}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Signal collection loop to stop (if it's running)
	if c.collectionActive {
		close(c.stopChan)
	}

	// Shutdown HTTP server
	if c.server != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		if err := c.server.Shutdown(shutdownCtx); err != nil {
			return &WrappedError{Msg: "failed to shutdown metrics server", Err: err}
		}
	}

	// Wait for collection loop to stop (if it was started)
	if c.collectionActive {
		<-c.stoppedChan
	}

	c.running.Store(false)
	return nil
}

// IsRunning returns whether the collector is running
func (c *Collector) IsRunning() bool {
	return c.running.Load()
}

// Metrics returns the metrics instance
func (c *Collector) Metrics() *Metrics {
	return c.metrics
}

// collectLoop periodically collects runtime and process metrics
func (c *Collector) collectLoop() {
	defer close(c.stoppedChan)

	ticker := time.NewTicker(c.config.CollectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.collectMetrics()
		}
	}
}

// collectMetrics collects current metrics snapshot
func (c *Collector) collectMetrics() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Update uptime
	uptime := time.Since(c.startTime).Seconds()
	c.metrics.DaemonUptime.Set(uptime)

	if c.config.EnableRuntimeMetrics {
		c.collectRuntimeMetrics()
	}

	if c.config.EnableProcessMetrics {
		c.collectProcessMetrics()
	}
}

// collectRuntimeMetrics collects Go runtime metrics
func (c *Collector) collectRuntimeMetrics() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Memory metrics
	c.metrics.MemoryUsage.WithLabelValues("alloc").Set(float64(m.Alloc))
	c.metrics.MemoryUsage.WithLabelValues("total_alloc").Set(float64(m.TotalAlloc))
	c.metrics.MemoryUsage.WithLabelValues("sys").Set(float64(m.Sys))
	c.metrics.MemoryUsage.WithLabelValues("heap_alloc").Set(float64(m.HeapAlloc))
	c.metrics.MemoryUsage.WithLabelValues("heap_sys").Set(float64(m.HeapSys))
	c.metrics.MemoryUsage.WithLabelValues("heap_idle").Set(float64(m.HeapIdle))
	c.metrics.MemoryUsage.WithLabelValues("heap_inuse").Set(float64(m.HeapInuse))
	c.metrics.MemoryUsage.WithLabelValues("stack_inuse").Set(float64(m.StackInuse))
	c.metrics.MemoryUsage.WithLabelValues("stack_sys").Set(float64(m.StackSys))

	// Goroutine count
	c.metrics.GoroutineCount.Set(float64(runtime.NumGoroutine()))
}

// collectProcessMetrics collects OS process metrics
func (c *Collector) collectProcessMetrics() {
	// File descriptor count (Unix-like systems)
	if fds, err := getOpenFileDescriptors(); err == nil {
		c.metrics.OpenFileDescriptors.Set(float64(fds))
	}

	// CPU usage would require additional tracking
	// This is a placeholder - actual implementation would need
	// to track CPU time deltas
}

// RegisterRuntimeCollector registers the collector with the default registry
func (c *Collector) RegisterRuntimeCollector() error {
	if !c.config.EnableRuntimeMetrics {
		return nil
	}

	collector := collectors.NewGoCollector()
	if err := prometheus.Register(collector); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			return ErrCollectorRegistration{Name: "go_collector", Err: err}
		}
	}

	return nil
}

// RegisterProcessCollector registers the process collector
func (c *Collector) RegisterProcessCollector() error {
	if !c.config.EnableProcessMetrics {
		return nil
	}

	collector := collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})
	if err := prometheus.Register(collector); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			return ErrCollectorRegistration{Name: "process_collector", Err: err}
		}
	}

	return nil
}

// Handler returns the HTTP handler for the metrics endpoint
func (c *Collector) Handler() http.Handler {
	return promhttp.Handler()
}

// Address returns the metrics server address
func (c *Collector) Address() string {
	return fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
}

// getOpenFileDescriptors returns the number of open file descriptors
// This is a placeholder implementation that would need to be platform-specific
func getOpenFileDescriptors() (int, error) {
	// On Linux, this would read /proc/self/fd
	// For now, return 0 as a safe default
	return 0, nil
}
