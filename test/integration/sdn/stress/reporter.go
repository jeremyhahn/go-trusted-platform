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
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// TableReporter formats results as an ASCII table.
type TableReporter struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewTableReporter creates a table reporter.
func NewTableReporter(w io.Writer) *TableReporter {
	return &TableReporter{writer: w}
}

// OnStart implements Reporter.
func (r *TableReporter) OnStart(config StressConfig) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Fprintln(r.writer, strings.Repeat("=", 60))
	fmt.Fprintf(r.writer, "Stress Test: %s\n", config.Name)
	fmt.Fprintln(r.writer, strings.Repeat("=", 60))
	fmt.Fprintf(r.writer, "Duration:     %s\n", config.Duration)
	fmt.Fprintf(r.writer, "Concurrency:  %d\n", config.Concurrency)
	if config.RateLimit > 0 {
		fmt.Fprintf(r.writer, "Rate Limit:   %d ops/s\n", config.RateLimit)
	} else {
		fmt.Fprintf(r.writer, "Rate Limit:   unlimited\n")
	}
	fmt.Fprintln(r.writer, strings.Repeat("-", 60))
	fmt.Fprintf(r.writer, "%-10s %-12s %-12s %-12s %-12s\n",
		"Elapsed", "Ops", "Success", "Errors", "Throughput")
	fmt.Fprintln(r.writer, strings.Repeat("-", 60))
}

// OnProgress implements Reporter.
func (r *TableReporter) OnProgress(report ProgressReport) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Fprintf(r.writer, "%-10s %-12d %-12d %-12d %-12.2f\n",
		report.Elapsed.Round(time.Second),
		report.Operations,
		report.Successes,
		report.Errors,
		report.CurrentThroughput)
}

// OnComplete implements Reporter.
func (r *TableReporter) OnComplete(result *StressResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Fprintln(r.writer, strings.Repeat("=", 60))
	fmt.Fprintln(r.writer, "RESULTS")
	fmt.Fprintln(r.writer, strings.Repeat("=", 60))

	fmt.Fprintf(r.writer, "%-25s %s\n", "Test Name:", result.TestName)
	fmt.Fprintf(r.writer, "%-25s %s\n", "Duration:", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(r.writer, "%-25s %d\n", "Total Operations:", result.TotalOperations)
	fmt.Fprintf(r.writer, "%-25s %d (%.2f%%)\n", "Successes:",
		result.SuccessCount, result.SuccessRate())
	fmt.Fprintf(r.writer, "%-25s %d\n", "Errors:", result.ErrorCount)
	fmt.Fprintf(r.writer, "%-25s %.2f ops/s\n", "Throughput:", result.Throughput)

	if result.Latencies != nil && result.Latencies.SampleCount > 0 {
		fmt.Fprintln(r.writer, strings.Repeat("-", 60))
		fmt.Fprintln(r.writer, "LATENCY DISTRIBUTION")
		fmt.Fprintln(r.writer, strings.Repeat("-", 60))
		fmt.Fprintf(r.writer, "%-25s %s\n", "Min:", result.Latencies.Min.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "%-25s %s\n", "Max:", result.Latencies.Max.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "%-25s %s\n", "Mean:", result.Latencies.Mean.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "%-25s %s\n", "P50 (Median):", result.Latencies.P50.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "%-25s %s\n", "P95:", result.Latencies.P95.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "%-25s %s\n", "P99:", result.Latencies.P99.Round(time.Microsecond))
		fmt.Fprintf(r.writer, "%-25s %s\n", "Std Dev:", result.Latencies.StdDev.Round(time.Microsecond))
	}

	if len(result.Errors) > 0 {
		fmt.Fprintln(r.writer, strings.Repeat("-", 60))
		fmt.Fprintln(r.writer, "ERROR BREAKDOWN")
		fmt.Fprintln(r.writer, strings.Repeat("-", 60))
		for msg, count := range result.Errors {
			fmt.Fprintf(r.writer, "%-45s %d\n", truncate(msg, 44), count)
		}
	}

	fmt.Fprintln(r.writer, strings.Repeat("=", 60))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// HistogramReporter displays a latency histogram.
type HistogramReporter struct {
	writer     io.Writer
	inner      Reporter
	buckets    []time.Duration
	bucketHits []int64
	mu         sync.Mutex
}

// NewHistogramReporter creates a histogram reporter with the given bucket boundaries.
func NewHistogramReporter(w io.Writer, inner Reporter, buckets []time.Duration) *HistogramReporter {
	return &HistogramReporter{
		writer:     w,
		inner:      inner,
		buckets:    buckets,
		bucketHits: make([]int64, len(buckets)+1),
	}
}

// DefaultHistogramBuckets returns common latency bucket boundaries.
func DefaultHistogramBuckets() []time.Duration {
	return []time.Duration{
		100 * time.Microsecond,
		500 * time.Microsecond,
		1 * time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
	}
}

// OnStart implements Reporter.
func (r *HistogramReporter) OnStart(config StressConfig) {
	if r.inner != nil {
		r.inner.OnStart(config)
	}
}

// OnProgress implements Reporter.
func (r *HistogramReporter) OnProgress(report ProgressReport) {
	if r.inner != nil {
		r.inner.OnProgress(report)
	}
}

// RecordLatency records a latency value into the appropriate bucket.
func (r *HistogramReporter) RecordLatency(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	bucketIdx := len(r.buckets) // Default to overflow bucket
	for i, boundary := range r.buckets {
		if d <= boundary {
			bucketIdx = i
			break
		}
	}
	r.bucketHits[bucketIdx]++
}

// OnComplete implements Reporter.
func (r *HistogramReporter) OnComplete(result *StressResult) {
	if r.inner != nil {
		r.inner.OnComplete(result)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Fprintln(r.writer, "\nLATENCY HISTOGRAM")
	fmt.Fprintln(r.writer, strings.Repeat("-", 70))

	var total int64
	for _, hits := range r.bucketHits {
		total += hits
	}

	if total == 0 {
		fmt.Fprintln(r.writer, "No samples recorded")
		return
	}

	maxHits := int64(0)
	for _, hits := range r.bucketHits {
		if hits > maxHits {
			maxHits = hits
		}
	}

	barWidth := 40
	for i := 0; i <= len(r.buckets); i++ {
		var label string
		if i == 0 {
			label = fmt.Sprintf("<= %s", r.buckets[0])
		} else if i < len(r.buckets) {
			label = fmt.Sprintf("<= %s", r.buckets[i])
		} else {
			label = fmt.Sprintf("> %s", r.buckets[len(r.buckets)-1])
		}

		hits := r.bucketHits[i]
		pct := float64(hits) / float64(total) * 100
		barLen := 0
		if maxHits > 0 {
			barLen = int(float64(hits) / float64(maxHits) * float64(barWidth))
		}
		bar := strings.Repeat("#", barLen)

		fmt.Fprintf(r.writer, "%-15s %8d (%5.1f%%) %s\n", label, hits, pct, bar)
	}
}

// MultiReporter sends reports to multiple reporters.
type MultiReporter struct {
	reporters []Reporter
}

// NewMultiReporter creates a reporter that forwards to multiple reporters.
func NewMultiReporter(reporters ...Reporter) *MultiReporter {
	return &MultiReporter{reporters: reporters}
}

// OnStart implements Reporter.
func (r *MultiReporter) OnStart(config StressConfig) {
	for _, reporter := range r.reporters {
		reporter.OnStart(config)
	}
}

// OnProgress implements Reporter.
func (r *MultiReporter) OnProgress(report ProgressReport) {
	for _, reporter := range r.reporters {
		reporter.OnProgress(report)
	}
}

// OnComplete implements Reporter.
func (r *MultiReporter) OnComplete(result *StressResult) {
	for _, reporter := range r.reporters {
		reporter.OnComplete(result)
	}
}

// MetricsReporter collects metrics that can be queried after the test.
type MetricsReporter struct {
	progressReports []ProgressReport
	result          *StressResult
	mu              sync.Mutex
}

// NewMetricsReporter creates a metrics collector reporter.
func NewMetricsReporter() *MetricsReporter {
	return &MetricsReporter{
		progressReports: make([]ProgressReport, 0, 100),
	}
}

// OnStart implements Reporter.
func (r *MetricsReporter) OnStart(config StressConfig) {}

// OnProgress implements Reporter.
func (r *MetricsReporter) OnProgress(report ProgressReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.progressReports = append(r.progressReports, report)
}

// OnComplete implements Reporter.
func (r *MetricsReporter) OnComplete(result *StressResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.result = result
}

// GetResult returns the final result.
func (r *MetricsReporter) GetResult() *StressResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.result
}

// GetProgressReports returns all progress reports.
func (r *MetricsReporter) GetProgressReports() []ProgressReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	reports := make([]ProgressReport, len(r.progressReports))
	copy(reports, r.progressReports)
	return reports
}

// ComparisonReporter compares results between test runs.
type ComparisonReporter struct {
	writer    io.Writer
	baseline  *StressResult
	threshold float64 // Maximum allowed regression percentage
}

// NewComparisonReporter creates a comparison reporter.
func NewComparisonReporter(w io.Writer, baseline *StressResult, regressionThreshold float64) *ComparisonReporter {
	return &ComparisonReporter{
		writer:    w,
		baseline:  baseline,
		threshold: regressionThreshold,
	}
}

// OnStart implements Reporter.
func (r *ComparisonReporter) OnStart(config StressConfig) {}

// OnProgress implements Reporter.
func (r *ComparisonReporter) OnProgress(report ProgressReport) {}

// OnComplete implements Reporter.
func (r *ComparisonReporter) OnComplete(result *StressResult) {
	if r.baseline == nil {
		fmt.Fprintln(r.writer, "No baseline for comparison")
		return
	}

	fmt.Fprintln(r.writer, "\nPERFORMANCE COMPARISON")
	fmt.Fprintln(r.writer, strings.Repeat("-", 70))
	fmt.Fprintf(r.writer, "%-25s %-15s %-15s %-15s\n", "Metric", "Baseline", "Current", "Change")
	fmt.Fprintln(r.writer, strings.Repeat("-", 70))

	r.compareMetric("Throughput (ops/s)", r.baseline.Throughput, result.Throughput, true)
	r.compareMetric("Success Rate (%)", r.baseline.SuccessRate(), result.SuccessRate(), true)

	if r.baseline.Latencies != nil && result.Latencies != nil {
		r.compareLatency("Latency P50", r.baseline.Latencies.P50, result.Latencies.P50)
		r.compareLatency("Latency P95", r.baseline.Latencies.P95, result.Latencies.P95)
		r.compareLatency("Latency P99", r.baseline.Latencies.P99, result.Latencies.P99)
	}
}

func (r *ComparisonReporter) compareMetric(name string, baseline, current float64, higherIsBetter bool) {
	if baseline == 0 {
		fmt.Fprintf(r.writer, "%-25s %-15.2f %-15.2f %-15s\n", name, baseline, current, "N/A")
		return
	}

	changePercent := ((current - baseline) / baseline) * 100
	changeStr := fmt.Sprintf("%.1f%%", changePercent)

	isRegression := (higherIsBetter && changePercent < -r.threshold) ||
		(!higherIsBetter && changePercent > r.threshold)

	if isRegression {
		changeStr += " [REGRESSION]"
	} else if changePercent > 0 == higherIsBetter {
		changeStr += " [IMPROVED]"
	}

	fmt.Fprintf(r.writer, "%-25s %-15.2f %-15.2f %-15s\n", name, baseline, current, changeStr)
}

func (r *ComparisonReporter) compareLatency(name string, baseline, current time.Duration) {
	if baseline == 0 {
		fmt.Fprintf(r.writer, "%-25s %-15s %-15s %-15s\n",
			name,
			baseline.Round(time.Microsecond).String(),
			current.Round(time.Microsecond).String(),
			"N/A")
		return
	}

	changePercent := (float64(current) - float64(baseline)) / float64(baseline) * 100
	changeStr := fmt.Sprintf("%.1f%%", changePercent)

	// For latency, lower is better
	if changePercent > r.threshold {
		changeStr += " [REGRESSION]"
	} else if changePercent < -r.threshold {
		changeStr += " [IMPROVED]"
	}

	fmt.Fprintf(r.writer, "%-25s %-15s %-15s %-15s\n",
		name,
		baseline.Round(time.Microsecond).String(),
		current.Round(time.Microsecond).String(),
		changeStr)
}

// ResultToJSON converts a StressResult to JSON.
func ResultToJSON(result *StressResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}

// ResultFromJSON parses a StressResult from JSON.
func ResultFromJSON(data []byte) (*StressResult, error) {
	var result StressResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
