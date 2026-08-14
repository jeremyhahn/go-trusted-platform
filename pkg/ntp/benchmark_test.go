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

package ntp

import (
	"context"
	"testing"
)

// BenchmarkRender measures chrony.conf rendering, which runs on every
// platformd start and on every config reload.
func BenchmarkRender(b *testing.B) {
	config := controlPlaneConfig()
	paths := DefaultPaths()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := Render(config, paths); err != nil {
			b.Fatalf("Render() error = %v", err)
		}
	}
}

// BenchmarkParseTracking measures the CSV decode on the status hot path: the
// startup gate polls it on a ticker and every health check calls it.
func BenchmarkParseTracking(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseTracking(syncedTrackingCSV); err != nil {
			b.Fatalf("parseTracking() error = %v", err)
		}
	}
}

// BenchmarkParseSources measures the source-enumeration decode.
func BenchmarkParseSources(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		if _, err := parseSources(sourcesCSV); err != nil {
			b.Fatalf("parseSources() error = %v", err)
		}
	}
}

// BenchmarkStatus measures the full status projection (tracking + source
// reachability + anomaly detection) that every transport serves.
func BenchmarkStatus(b *testing.B) {
	controller := &fakeController{
		tracking: []*Tracking{syncedTracking()},
		sources: []Source{
			{Address: "198.18.0.1", Reach: 377, Reachable: true},
			{Address: "203.0.113.9", Reach: 0, Reachable: false},
		},
	}
	service, err := NewService(controlPlaneConfig(),
		WithPaths(testPaths()),
		WithLogger(quietLogger()),
		WithController(controller),
	)
	if err != nil {
		b.Fatalf("NewService() error = %v", err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		if _, err := service.Status(ctx); err != nil {
			b.Fatalf("Status() error = %v", err)
		}
	}
}

// BenchmarkValidate measures configuration validation, which gates every
// service construction and every template guard check.
func BenchmarkValidate(b *testing.B) {
	config := controlPlaneConfig()

	b.ReportAllocs()
	for b.Loop() {
		if err := config.Validate(); err != nil {
			b.Fatalf("Validate() error = %v", err)
		}
	}
}
