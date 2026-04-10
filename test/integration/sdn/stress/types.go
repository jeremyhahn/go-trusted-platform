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

// Package stress provides stress testing utilities for SDN components.
// It validates behavior under high load, concurrent access, and resource exhaustion scenarios.

//go:build integration

package stress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// StressConfig configures a stress test run.
type StressConfig struct {
	// Duration specifies how long the stress test should run.
	Duration time.Duration

	// Concurrency specifies the number of concurrent workers.
	Concurrency int

	// RateLimit specifies maximum operations per second (0 = unlimited).
	RateLimit int

	// ReportInterval specifies how often to report progress during the test.
	ReportInterval time.Duration

	// WarmupDuration specifies a warmup period before measuring.
	WarmupDuration time.Duration

	// Name is an optional name for the stress test.
	Name string
}

// DefaultConfig returns a StressConfig with sensible defaults.
func DefaultConfig() StressConfig {
	return StressConfig{
		Duration:       30 * time.Second,
		Concurrency:    10,
		RateLimit:      0,
		ReportInterval: 5 * time.Second,
		WarmupDuration: 2 * time.Second,
	}
}

// Validate checks if the configuration is valid.
func (c *StressConfig) Validate() error {
	if c.Duration <= 0 {
		return ErrInvalidDuration
	}
	if c.Concurrency <= 0 {
		return ErrInvalidConcurrency
	}
	if c.RateLimit < 0 {
		return ErrInvalidRateLimit
	}
	if c.ReportInterval <= 0 {
		c.ReportInterval = 5 * time.Second
	}
	return nil
}

// StressResult contains the results of a stress test run.
type StressResult struct {
	// TestName identifies the stress test.
	TestName string `json:"test_name"`

	// Duration is the actual test duration.
	Duration time.Duration `json:"duration"`

	// TotalOperations is the total number of operations attempted.
	TotalOperations int64 `json:"total_operations"`

	// SuccessCount is the number of successful operations.
	SuccessCount int64 `json:"success_count"`

	// ErrorCount is the number of failed operations.
	ErrorCount int64 `json:"error_count"`

	// Latencies contains latency statistics.
	Latencies *LatencyStats `json:"latencies"`

	// Errors maps error messages to their occurrence counts.
	Errors map[string]int64 `json:"errors,omitempty"`

	// Throughput is operations per second.
	Throughput float64 `json:"throughput"`

	// StartTime is when the test started.
	StartTime time.Time `json:"start_time"`

	// EndTime is when the test ended.
	EndTime time.Time `json:"end_time"`

	// CustomMetrics holds test-specific metrics.
	CustomMetrics map[string]float64 `json:"custom_metrics,omitempty"`
}

// SuccessRate returns the percentage of successful operations.
func (r *StressResult) SuccessRate() float64 {
	if r.TotalOperations == 0 {
		return 0
	}
	return float64(r.SuccessCount) / float64(r.TotalOperations) * 100
}

// LatencyStats contains latency distribution statistics.
type LatencyStats struct {
	// Min is the minimum observed latency.
	Min time.Duration `json:"min"`

	// Max is the maximum observed latency.
	Max time.Duration `json:"max"`

	// Mean is the average latency.
	Mean time.Duration `json:"mean"`

	// P50 is the 50th percentile (median) latency.
	P50 time.Duration `json:"p50"`

	// P95 is the 95th percentile latency.
	P95 time.Duration `json:"p95"`

	// P99 is the 99th percentile latency.
	P99 time.Duration `json:"p99"`

	// StdDev is the standard deviation.
	StdDev time.Duration `json:"std_dev"`

	// SampleCount is the number of samples used for calculation.
	SampleCount int64 `json:"sample_count"`
}

// LatencyCollector collects latency samples and computes statistics.
// It is safe for concurrent use.
type LatencyCollector struct {
	samples []time.Duration
	mu      sync.Mutex
	count   atomic.Int64
}

// NewLatencyCollector creates a new latency collector with pre-allocated capacity.
func NewLatencyCollector(expectedSamples int) *LatencyCollector {
	return &LatencyCollector{
		samples: make([]time.Duration, 0, expectedSamples),
	}
}

// Record records a latency sample.
func (c *LatencyCollector) Record(d time.Duration) {
	c.mu.Lock()
	c.samples = append(c.samples, d)
	c.mu.Unlock()
	c.count.Add(1)
}

// Count returns the number of recorded samples.
func (c *LatencyCollector) Count() int64 {
	return c.count.Load()
}

// Stats computes latency statistics from collected samples.
func (c *LatencyCollector) Stats() *LatencyStats {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.samples) == 0 {
		return &LatencyStats{}
	}

	// Sort for percentile calculation
	sorted := make([]time.Duration, len(c.samples))
	copy(sorted, c.samples)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	n := len(sorted)
	var sum int64
	for _, d := range sorted {
		sum += int64(d)
	}

	mean := time.Duration(sum / int64(n))

	// Calculate standard deviation
	var variance float64
	for _, d := range sorted {
		diff := float64(d - mean)
		variance += diff * diff
	}
	variance /= float64(n)
	stdDev := time.Duration(math.Sqrt(variance))

	return &LatencyStats{
		Min:         sorted[0],
		Max:         sorted[n-1],
		Mean:        mean,
		P50:         sorted[percentileIndex(n, 50)],
		P95:         sorted[percentileIndex(n, 95)],
		P99:         sorted[percentileIndex(n, 99)],
		StdDev:      stdDev,
		SampleCount: int64(n),
	}
}

func percentileIndex(n int, p int) int {
	idx := (n * p) / 100
	if idx >= n {
		idx = n - 1
	}
	return idx
}

// ErrorTracker tracks error occurrences by message.
// It is safe for concurrent use.
type ErrorTracker struct {
	errors map[string]*atomic.Int64
	mu     sync.RWMutex
	total  atomic.Int64
}

// NewErrorTracker creates a new error tracker.
func NewErrorTracker() *ErrorTracker {
	return &ErrorTracker{
		errors: make(map[string]*atomic.Int64),
	}
}

// Record records an error occurrence.
func (t *ErrorTracker) Record(err error) {
	if err == nil {
		return
	}

	msg := err.Error()
	t.mu.Lock()
	counter, exists := t.errors[msg]
	if !exists {
		counter = &atomic.Int64{}
		t.errors[msg] = counter
	}
	t.mu.Unlock()

	counter.Add(1)
	t.total.Add(1)
}

// Total returns the total number of errors recorded.
func (t *ErrorTracker) Total() int64 {
	return t.total.Load()
}

// Snapshot returns a copy of the error counts.
func (t *ErrorTracker) Snapshot() map[string]int64 {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]int64, len(t.errors))
	for msg, counter := range t.errors {
		result[msg] = counter.Load()
	}
	return result
}

// ProgressReport contains intermediate progress information.
type ProgressReport struct {
	// Elapsed is the time since the test started.
	Elapsed time.Duration `json:"elapsed"`

	// Operations is the total operations so far.
	Operations int64 `json:"operations"`

	// Successes is the successful operations so far.
	Successes int64 `json:"successes"`

	// Errors is the failed operations so far.
	Errors int64 `json:"errors"`

	// CurrentThroughput is the recent throughput.
	CurrentThroughput float64 `json:"current_throughput"`

	// AverageLatency is the recent average latency.
	AverageLatency time.Duration `json:"average_latency"`
}

// Operation represents a single stress test operation.
type Operation func(ctx context.Context) error

// OperationResult represents the result of a single operation.
type OperationResult struct {
	Success  bool
	Duration time.Duration
	Error    error
}

// RateLimiter controls the rate of operations.
type RateLimiter struct {
	interval time.Duration
	ticker   *time.Ticker
	tokens   chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewRateLimiter creates a rate limiter for the specified ops/sec.
// If rate is 0 or negative, returns nil (unlimited).
func NewRateLimiter(opsPerSecond int) *RateLimiter {
	if opsPerSecond <= 0 {
		return nil
	}

	interval := time.Second / time.Duration(opsPerSecond)
	rl := &RateLimiter{
		interval: interval,
		ticker:   time.NewTicker(interval),
		tokens:   make(chan struct{}, 1),
		stopCh:   make(chan struct{}),
	}

	go rl.run()
	return rl
}

func (r *RateLimiter) run() {
	for {
		select {
		case <-r.stopCh:
			r.ticker.Stop()
			return
		case <-r.ticker.C:
			select {
			case r.tokens <- struct{}{}:
			default:
				// Token channel full, skip
			}
		}
	}
}

// Wait waits for permission to perform an operation.
// Returns false if the context is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) bool {
	if r == nil {
		return true // No rate limiting
	}

	select {
	case <-ctx.Done():
		return false
	case <-r.tokens:
		return true
	}
}

// Stop stops the rate limiter.
func (r *RateLimiter) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

// Reporter handles progress reporting during stress tests.
type Reporter interface {
	// OnStart is called when the test starts.
	OnStart(config StressConfig)

	// OnProgress is called periodically with progress updates.
	OnProgress(report ProgressReport)

	// OnComplete is called when the test completes.
	OnComplete(result *StressResult)
}

// ConsoleReporter reports progress to an io.Writer.
type ConsoleReporter struct {
	writer io.Writer
}

// NewConsoleReporter creates a console reporter writing to the given writer.
func NewConsoleReporter(w io.Writer) *ConsoleReporter {
	return &ConsoleReporter{writer: w}
}

// OnStart implements Reporter.
func (r *ConsoleReporter) OnStart(config StressConfig) {
	fmt.Fprintf(r.writer, "Starting stress test: %s\n", config.Name)
	fmt.Fprintf(r.writer, "  Duration: %s, Concurrency: %d, Rate Limit: %d ops/s\n",
		config.Duration, config.Concurrency, config.RateLimit)
}

// OnProgress implements Reporter.
func (r *ConsoleReporter) OnProgress(report ProgressReport) {
	fmt.Fprintf(r.writer, "[%s] ops=%d success=%d errors=%d throughput=%.2f ops/s latency=%s\n",
		report.Elapsed.Round(time.Second),
		report.Operations,
		report.Successes,
		report.Errors,
		report.CurrentThroughput,
		report.AverageLatency.Round(time.Microsecond))
}

// OnComplete implements Reporter.
func (r *ConsoleReporter) OnComplete(result *StressResult) {
	fmt.Fprintf(r.writer, "\nStress test completed: %s\n", result.TestName)
	fmt.Fprintf(r.writer, "  Duration: %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(r.writer, "  Total Operations: %d\n", result.TotalOperations)
	fmt.Fprintf(r.writer, "  Successes: %d (%.2f%%)\n", result.SuccessCount, result.SuccessRate())
	fmt.Fprintf(r.writer, "  Errors: %d\n", result.ErrorCount)
	fmt.Fprintf(r.writer, "  Throughput: %.2f ops/s\n", result.Throughput)

	if result.Latencies != nil && result.Latencies.SampleCount > 0 {
		fmt.Fprintf(r.writer, "  Latency:\n")
		fmt.Fprintf(r.writer, "    Min: %s\n", result.Latencies.Min.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "    Max: %s\n", result.Latencies.Max.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "    Mean: %s\n", result.Latencies.Mean.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "    P50: %s\n", result.Latencies.P50.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "    P95: %s\n", result.Latencies.P95.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "    P99: %s\n", result.Latencies.P99.Round(time.Microsecond))
	}

	if len(result.Errors) > 0 {
		fmt.Fprintf(r.writer, "  Error breakdown:\n")
		for msg, count := range result.Errors {
			fmt.Fprintf(r.writer, "    %s: %d\n", msg, count)
		}
	}
}

// JSONReporter reports results as JSON.
type JSONReporter struct {
	writer io.Writer
}

// NewJSONReporter creates a JSON reporter writing to the given writer.
func NewJSONReporter(w io.Writer) *JSONReporter {
	return &JSONReporter{writer: w}
}

// OnStart implements Reporter.
func (r *JSONReporter) OnStart(config StressConfig) {
	// No output on start for JSON reporter
}

// OnProgress implements Reporter.
func (r *JSONReporter) OnProgress(report ProgressReport) {
	// No intermediate output for JSON reporter
}

// OnComplete implements Reporter.
func (r *JSONReporter) OnComplete(result *StressResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(r.writer, `{"error": "failed to marshal result: %s"}`, err.Error())
		return
	}
	fmt.Fprintln(r.writer, string(data))
}

// NullReporter discards all reports.
type NullReporter struct{}

// OnStart implements Reporter.
func (r *NullReporter) OnStart(config StressConfig) {}

// OnProgress implements Reporter.
func (r *NullReporter) OnProgress(report ProgressReport) {}

// OnComplete implements Reporter.
func (r *NullReporter) OnComplete(result *StressResult) {}
