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
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// BenchmarkCounter_Inc benchmarks counter increment operations.
func BenchmarkCounter_Inc(b *testing.B) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "benchmark_counter_total",
		Help: "Benchmark counter",
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		counter.Inc()
	}
}

// BenchmarkCounter_Inc_Parallel benchmarks concurrent counter increment.
func BenchmarkCounter_Inc_Parallel(b *testing.B) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "benchmark_counter_parallel_total",
		Help: "Benchmark counter for parallel access",
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			counter.Inc()
		}
	})
}

// BenchmarkCounter_Add benchmarks counter add operations.
func BenchmarkCounter_Add(b *testing.B) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "benchmark_counter_add_total",
		Help: "Benchmark counter for add",
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		counter.Add(float64(i % 100))
	}
}

// BenchmarkCounterVec_WithLabelValues benchmarks labeled counter operations.
func BenchmarkCounterVec_WithLabelValues(b *testing.B) {
	counterVec := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "benchmark_counter_vec_total",
			Help: "Benchmark counter vector",
		},
		[]string{"label1", "label2"},
	)

	labels := [][]string{
		{"value1", "value2"},
		{"value3", "value4"},
		{"value5", "value6"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		l := labels[i%len(labels)]
		counterVec.WithLabelValues(l[0], l[1]).Inc()
	}
}

// BenchmarkCounterVec_WithLabelValues_Parallel benchmarks concurrent labeled counter.
func BenchmarkCounterVec_WithLabelValues_Parallel(b *testing.B) {
	counterVec := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "benchmark_counter_vec_parallel_total",
			Help: "Benchmark counter vector for parallel access",
		},
		[]string{"label1", "label2"},
	)

	labels := [][]string{
		{"value1", "value2"},
		{"value3", "value4"},
		{"value5", "value6"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			l := labels[counter%len(labels)]
			counterVec.WithLabelValues(l[0], l[1]).Inc()
		}
	})
}

// BenchmarkGauge_Set benchmarks gauge set operations.
func BenchmarkGauge_Set(b *testing.B) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "benchmark_gauge",
		Help: "Benchmark gauge",
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		gauge.Set(float64(i))
	}
}

// BenchmarkGauge_Set_Parallel benchmarks concurrent gauge set.
func BenchmarkGauge_Set_Parallel(b *testing.B) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "benchmark_gauge_parallel",
		Help: "Benchmark gauge for parallel access",
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			gauge.Set(float64(counter))
		}
	})
}

// BenchmarkGauge_Inc benchmarks gauge increment operations.
func BenchmarkGauge_Inc(b *testing.B) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "benchmark_gauge_inc",
		Help: "Benchmark gauge for increment",
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		gauge.Inc()
	}
}

// BenchmarkGauge_Dec benchmarks gauge decrement operations.
func BenchmarkGauge_Dec(b *testing.B) {
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "benchmark_gauge_dec",
		Help: "Benchmark gauge for decrement",
	})
	gauge.Set(float64(1000000))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		gauge.Dec()
	}
}

// BenchmarkGaugeVec_WithLabelValues benchmarks labeled gauge operations.
func BenchmarkGaugeVec_WithLabelValues(b *testing.B) {
	gaugeVec := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "benchmark_gauge_vec",
			Help: "Benchmark gauge vector",
		},
		[]string{"service", "instance"},
	)

	labels := [][]string{
		{"svc1", "instance1"},
		{"svc2", "instance2"},
		{"svc3", "instance3"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		l := labels[i%len(labels)]
		gaugeVec.WithLabelValues(l[0], l[1]).Set(float64(i))
	}
}

// BenchmarkHistogram_Observe benchmarks histogram observe operations.
func BenchmarkHistogram_Observe(b *testing.B) {
	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "benchmark_histogram",
		Help:    "Benchmark histogram",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		histogram.Observe(float64(i%100) / 100.0)
	}
}

// BenchmarkHistogram_Observe_Parallel benchmarks concurrent histogram observe.
func BenchmarkHistogram_Observe_Parallel(b *testing.B) {
	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "benchmark_histogram_parallel",
		Help:    "Benchmark histogram for parallel access",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			histogram.Observe(float64(counter%100) / 100.0)
		}
	})
}

// BenchmarkHistogramVec_WithLabelValues benchmarks labeled histogram operations.
func BenchmarkHistogramVec_WithLabelValues(b *testing.B) {
	histogramVec := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "benchmark_histogram_vec",
			Help:    "Benchmark histogram vector",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	labels := [][]string{
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/users"},
		{"GET", "/api/v1/tenants"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		l := labels[i%len(labels)]
		histogramVec.WithLabelValues(l[0], l[1]).Observe(float64(i%100) / 100.0)
	}
}

// BenchmarkHistogramVec_WithLabelValues_Parallel benchmarks concurrent labeled histogram.
func BenchmarkHistogramVec_WithLabelValues_Parallel(b *testing.B) {
	histogramVec := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "benchmark_histogram_vec_parallel",
			Help:    "Benchmark histogram vector for parallel access",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	labels := [][]string{
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/users"},
		{"GET", "/api/v1/tenants"},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		counter := 0
		for pb.Next() {
			counter++
			l := labels[counter%len(labels)]
			histogramVec.WithLabelValues(l[0], l[1]).Observe(float64(counter%100) / 100.0)
		}
	})
}

// BenchmarkSummary_Observe benchmarks summary observe operations.
func BenchmarkSummary_Observe(b *testing.B) {
	summary := prometheus.NewSummary(prometheus.SummaryOpts{
		Name:       "benchmark_summary",
		Help:       "Benchmark summary",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		summary.Observe(float64(i%100) / 100.0)
	}
}

// BenchmarkMetricName benchmarks metric name construction.
func BenchmarkMetricName(b *testing.B) {
	m := &Metrics{
		config: &Config{
			Namespace: "trusted_platform",
		},
	}

	subsystems := []string{"sdn", "certificate", "http", "grpc", "system"}
	names := []string{"operations_total", "duration_seconds", "errors_total"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		subsystem := subsystems[i%len(subsystems)]
		name := names[i%len(names)]
		_ = m.MetricName(subsystem, name)
	}
}

// BenchmarkConfig_Validate benchmarks configuration validation.
func BenchmarkConfig_Validate(b *testing.B) {
	config := &Config{
		Enabled:         true,
		Namespace:       "trusted_platform",
		Port:            9090,
		Path:            "/metrics",
		Host:            "localhost",
		CollectInterval: 15 * time.Second,
		Labels: map[string]string{
			"environment": "production",
		},
		BucketDefaults: HistogramBuckets{
			Latency:  []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
			Duration: []float64{.1, .5, 1, 2, 5, 10, 30, 60, 120, 300},
			Size:     []float64{100, 1000, 10000, 100000, 1000000, 10000000},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = config.Validate()
	}
}

// BenchmarkHistogram_BucketSizes benchmarks histograms with different bucket counts.
func BenchmarkHistogram_BucketSizes(b *testing.B) {
	bucketCounts := []int{5, 10, 20, 50}

	for _, count := range bucketCounts {
		b.Run(fmt.Sprintf("Buckets_%d", count), func(b *testing.B) {
			buckets := make([]float64, count)
			for i := 0; i < count; i++ {
				buckets[i] = float64(i+1) * 0.01
			}

			histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
				Name:    fmt.Sprintf("benchmark_histogram_buckets_%d", count),
				Help:    "Benchmark histogram with variable buckets",
				Buckets: buckets,
			})

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				histogram.Observe(float64(i%100) / 100.0)
			}
		})
	}
}

// BenchmarkCounterVec_LabelCardinality benchmarks counters with different label cardinalities.
func BenchmarkCounterVec_LabelCardinality(b *testing.B) {
	cardinalities := []int{10, 100, 1000}

	for _, card := range cardinalities {
		b.Run(fmt.Sprintf("Cardinality_%d", card), func(b *testing.B) {
			counterVec := prometheus.NewCounterVec(
				prometheus.CounterOpts{
					Name: fmt.Sprintf("benchmark_counter_cardinality_%d", card),
					Help: "Benchmark counter with variable cardinality",
				},
				[]string{"label"},
			)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				label := fmt.Sprintf("value_%d", i%card)
				counterVec.WithLabelValues(label).Inc()
			}
		})
	}
}

// BenchmarkMixedMetricWorkload benchmarks a realistic mixed workload.
func BenchmarkMixedMetricWorkload(b *testing.B) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "benchmark_mixed_counter_total",
		Help: "Benchmark mixed counter",
	})

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "benchmark_mixed_gauge",
		Help: "Benchmark mixed gauge",
	})

	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "benchmark_mixed_histogram",
		Help:    "Benchmark mixed histogram",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		switch i % 10 {
		case 0, 1, 2, 3: // 40% counter increments
			counter.Inc()
		case 4, 5: // 20% gauge sets
			gauge.Set(float64(i))
		default: // 40% histogram observations
			histogram.Observe(float64(i%100) / 100.0)
		}
	}
}

// BenchmarkMixedMetricWorkload_Parallel benchmarks concurrent mixed workload.
func BenchmarkMixedMetricWorkload_Parallel(b *testing.B) {
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "benchmark_mixed_parallel_counter_total",
		Help: "Benchmark mixed parallel counter",
	})

	gauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "benchmark_mixed_parallel_gauge",
		Help: "Benchmark mixed parallel gauge",
	})

	histogram := prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "benchmark_mixed_parallel_histogram",
		Help:    "Benchmark mixed parallel histogram",
		Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
	})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			switch i % 10 {
			case 0, 1, 2, 3:
				counter.Inc()
			case 4, 5:
				gauge.Set(float64(i))
			default:
				histogram.Observe(float64(i%100) / 100.0)
			}
		}
	})
}

// BenchmarkDefaultConfig benchmarks default configuration creation.
func BenchmarkDefaultConfig(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = DefaultConfig()
	}
}

// BenchmarkDefaultHistogramBuckets benchmarks default histogram buckets creation.
func BenchmarkDefaultHistogramBuckets(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = DefaultHistogramBuckets()
	}
}
