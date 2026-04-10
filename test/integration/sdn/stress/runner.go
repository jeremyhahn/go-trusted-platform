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

package stress

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// Runner executes stress tests with configurable concurrency and rate limiting.
type Runner struct {
	config      StressConfig
	operation   Operation
	reporter    Reporter
	rateLimiter *RateLimiter

	// Metrics
	latencies    *LatencyCollector
	errors       *ErrorTracker
	totalOps     atomic.Int64
	successCount atomic.Int64
	errorCount   atomic.Int64

	// State
	running  atomic.Bool
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// Progress tracking
	lastReportOps  atomic.Int64
	lastReportTime atomic.Value // time.Time
}

// NewRunner creates a new stress test runner.
func NewRunner(config StressConfig, op Operation, reporter Reporter) (*Runner, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if op == nil {
		return nil, &StressError{Code: "NIL_OPERATION", Message: "operation cannot be nil"}
	}
	if reporter == nil {
		reporter = &NullReporter{}
	}

	expectedSamples := config.Concurrency * int(config.Duration/time.Millisecond)
	if expectedSamples > 1000000 {
		expectedSamples = 1000000 // Cap at 1M samples
	}

	r := &Runner{
		config:    config,
		operation: op,
		reporter:  reporter,
		latencies: NewLatencyCollector(expectedSamples),
		errors:    NewErrorTracker(),
		stopCh:    make(chan struct{}),
	}

	if config.RateLimit > 0 {
		r.rateLimiter = NewRateLimiter(config.RateLimit)
	}

	return r, nil
}

// Run executes the stress test and returns the results.
func (r *Runner) Run(ctx context.Context) (*StressResult, error) {
	if !r.running.CompareAndSwap(false, true) {
		return nil, ErrRunnerAlreadyRunning
	}
	defer r.running.Store(false)

	// Create test context with deadline
	testCtx, cancel := context.WithTimeout(ctx, r.config.Duration+r.config.WarmupDuration)
	defer cancel()

	r.reporter.OnStart(r.config)

	startTime := time.Now()
	r.lastReportTime.Store(startTime)

	// Start workers
	for i := 0; i < r.config.Concurrency; i++ {
		r.wg.Add(1)
		go r.worker(testCtx)
	}

	// Start progress reporter
	progressDone := make(chan struct{})
	go r.progressLoop(testCtx, startTime, progressDone)

	// Wait for deadline or stop signal
	select {
	case <-testCtx.Done():
		// Normal completion or cancellation
	case <-r.stopCh:
		cancel() // Cancel test context
	}

	// Wait for workers to finish
	r.wg.Wait()
	close(progressDone)

	// Stop rate limiter
	if r.rateLimiter != nil {
		r.rateLimiter.Stop()
	}

	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Build result
	result := &StressResult{
		TestName:        r.config.Name,
		Duration:        duration,
		TotalOperations: r.totalOps.Load(),
		SuccessCount:    r.successCount.Load(),
		ErrorCount:      r.errorCount.Load(),
		Latencies:       r.latencies.Stats(),
		Errors:          r.errors.Snapshot(),
		StartTime:       startTime,
		EndTime:         endTime,
	}

	if duration > 0 {
		result.Throughput = float64(result.TotalOperations) / duration.Seconds()
	}

	r.reporter.OnComplete(result)

	return result, nil
}

// Stop signals the runner to stop gracefully.
func (r *Runner) Stop() {
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}

// worker runs operations in a loop until the context is done.
func (r *Runner) worker(ctx context.Context) {
	defer r.wg.Done()

	// Warmup phase
	if r.config.WarmupDuration > 0 {
		warmupDeadline := time.After(r.config.WarmupDuration)
	warmupLoop:
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopCh:
				return
			case <-warmupDeadline:
				break warmupLoop
			default:
				if r.rateLimiter != nil && !r.rateLimiter.Wait(ctx) {
					return
				}
				_ = r.operation(ctx) // Ignore warmup results
			}
		}
	}

	// Main test loop
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		default:
			if r.rateLimiter != nil && !r.rateLimiter.Wait(ctx) {
				return
			}

			start := time.Now()
			err := r.operation(ctx)
			duration := time.Since(start)

			r.totalOps.Add(1)
			r.latencies.Record(duration)

			if err != nil {
				r.errorCount.Add(1)
				r.errors.Record(err)
			} else {
				r.successCount.Add(1)
			}
		}
	}
}

// progressLoop reports progress at regular intervals.
func (r *Runner) progressLoop(ctx context.Context, startTime time.Time, done <-chan struct{}) {
	ticker := time.NewTicker(r.config.ReportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reportProgress(startTime)
		}
	}
}

func (r *Runner) reportProgress(startTime time.Time) {
	now := time.Now()
	elapsed := now.Sub(startTime)
	ops := r.totalOps.Load()
	lastOps := r.lastReportOps.Swap(ops)

	lastTimeVal := r.lastReportTime.Load()
	lastTime, ok := lastTimeVal.(time.Time)
	if !ok {
		lastTime = startTime
	}
	r.lastReportTime.Store(now)

	interval := now.Sub(lastTime)
	var currentThroughput float64
	if interval > 0 {
		currentThroughput = float64(ops-lastOps) / interval.Seconds()
	}

	var avgLatency time.Duration
	stats := r.latencies.Stats()
	if stats != nil && stats.SampleCount > 0 {
		avgLatency = stats.Mean
	}

	report := ProgressReport{
		Elapsed:           elapsed,
		Operations:        ops,
		Successes:         r.successCount.Load(),
		Errors:            r.errorCount.Load(),
		CurrentThroughput: currentThroughput,
		AverageLatency:    avgLatency,
	}

	r.reporter.OnProgress(report)
}

// RunnerOption configures a Runner.
type RunnerOption func(*Runner)

// WithReporter sets the progress reporter.
func WithReporter(r Reporter) RunnerOption {
	return func(runner *Runner) {
		runner.reporter = r
	}
}

// RunStressTest is a convenience function to run a stress test with default options.
func RunStressTest(ctx context.Context, name string, config StressConfig, op Operation, reporter Reporter) (*StressResult, error) {
	config.Name = name
	runner, err := NewRunner(config, op, reporter)
	if err != nil {
		return nil, err
	}
	return runner.Run(ctx)
}

// ConcurrentRunner runs multiple operations concurrently and waits for all to complete.
type ConcurrentRunner struct {
	operations []Operation
	timeout    time.Duration
}

// NewConcurrentRunner creates a runner for executing multiple operations concurrently.
func NewConcurrentRunner(timeout time.Duration) *ConcurrentRunner {
	return &ConcurrentRunner{
		timeout: timeout,
	}
}

// AddOperation adds an operation to run.
func (r *ConcurrentRunner) AddOperation(op Operation) {
	r.operations = append(r.operations, op)
}

// Run executes all operations concurrently and returns their results.
func (r *ConcurrentRunner) Run(ctx context.Context) []OperationResult {
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	results := make([]OperationResult, len(r.operations))
	var wg sync.WaitGroup

	for i, op := range r.operations {
		wg.Add(1)
		go func(idx int, operation Operation) {
			defer wg.Done()

			start := time.Now()
			err := operation(ctx)
			duration := time.Since(start)

			results[idx] = OperationResult{
				Success:  err == nil,
				Duration: duration,
				Error:    err,
			}
		}(i, op)
	}

	wg.Wait()
	return results
}

// BatchRunner runs operations in batches with configurable batch size.
type BatchRunner struct {
	batchSize int
	delay     time.Duration
	reporter  Reporter
}

// NewBatchRunner creates a batch runner.
func NewBatchRunner(batchSize int, delay time.Duration, reporter Reporter) *BatchRunner {
	if reporter == nil {
		reporter = &NullReporter{}
	}
	return &BatchRunner{
		batchSize: batchSize,
		delay:     delay,
		reporter:  reporter,
	}
}

// Run executes operations in batches.
func (r *BatchRunner) Run(ctx context.Context, operations []Operation) ([]OperationResult, error) {
	results := make([]OperationResult, len(operations))
	batchNum := 0

	for i := 0; i < len(operations); i += r.batchSize {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		end := i + r.batchSize
		if end > len(operations) {
			end = len(operations)
		}

		batch := operations[i:end]
		batchResults := r.runBatch(ctx, batch)

		copy(results[i:end], batchResults)
		batchNum++

		// Delay between batches
		if r.delay > 0 && end < len(operations) {
			select {
			case <-ctx.Done():
				return results, ctx.Err()
			case <-time.After(r.delay):
			}
		}
	}

	return results, nil
}

func (r *BatchRunner) runBatch(ctx context.Context, operations []Operation) []OperationResult {
	results := make([]OperationResult, len(operations))
	var wg sync.WaitGroup

	for i, op := range operations {
		wg.Add(1)
		go func(idx int, operation Operation) {
			defer wg.Done()

			start := time.Now()
			err := operation(ctx)
			duration := time.Since(start)

			results[idx] = OperationResult{
				Success:  err == nil,
				Duration: duration,
				Error:    err,
			}
		}(i, op)
	}

	wg.Wait()
	return results
}
