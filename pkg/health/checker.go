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

package health

import (
	"context"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// HealthChecker is the interface that all health checkers must implement.
type HealthChecker interface {
	// Name returns the unique identifier for this health checker.
	Name() string

	// Check performs the health check and returns the component health status.
	Check(ctx context.Context) ComponentHealth
}

// QuicBaaSChecker checks the health of a QuicBaaS connection.
type QuicBaaSChecker struct {
	name     string
	pingFunc func(ctx context.Context) error
}

// QuicBaaSCheckerOption is a functional option for configuring QuicBaaSChecker.
type QuicBaaSCheckerOption func(*QuicBaaSChecker)

// WithQuicBaaSName sets the name for the QuicBaaS checker.
func WithQuicBaaSName(name string) QuicBaaSCheckerOption {
	return func(c *QuicBaaSChecker) {
		c.name = name
	}
}

// NewQuicBaaSChecker creates a new QuicBaaS health checker.
// The pingFunc should return nil if QuicBaaS is healthy, or an error otherwise.
func NewQuicBaaSChecker(pingFunc func(ctx context.Context) error, opts ...QuicBaaSCheckerOption) *QuicBaaSChecker {
	c := &QuicBaaSChecker{
		name:     "quicbaas",
		pingFunc: pingFunc,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the unique identifier for this health checker.
func (c *QuicBaaSChecker) Name() string {
	return c.name
}

// Check performs the health check for QuicBaaS.
func (c *QuicBaaSChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()
	health := ComponentHealth{
		Name:        c.name,
		Status:      StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.pingFunc == nil {
		health.Status = StatusUnhealthy
		health.Message = "ping function not configured"
		health.Duration = time.Since(start)
		return health
	}

	err := c.pingFunc(ctx)
	health.Duration = time.Since(start)

	if err != nil {
		health.Status = StatusUnhealthy
		health.Message = err.Error()
		health.Details["error"] = err.Error()
		return health
	}

	health.Status = StatusHealthy
	health.Message = "QuicBaaS is responding"
	health.Details["response_time_ms"] = float64(health.Duration.Microseconds()) / 1000.0
	return health
}

// OVSChecker checks the health of an Open vSwitch connection.
type OVSChecker struct {
	name       string
	socketPath string
	checkFunc  func(ctx context.Context) error
}

// OVSCheckerOption is a functional option for configuring OVSChecker.
type OVSCheckerOption func(*OVSChecker)

// WithOVSName sets the name for the OVS checker.
func WithOVSName(name string) OVSCheckerOption {
	return func(c *OVSChecker) {
		c.name = name
	}
}

// WithOVSSocketPath sets the socket path for OVS checker.
func WithOVSSocketPath(path string) OVSCheckerOption {
	return func(c *OVSChecker) {
		c.socketPath = path
	}
}

// NewOVSChecker creates a new OVS health checker.
// The checkFunc should return nil if OVS is healthy, or an error otherwise.
func NewOVSChecker(checkFunc func(ctx context.Context) error, opts ...OVSCheckerOption) *OVSChecker {
	c := &OVSChecker{
		name:       "ovs",
		socketPath: "/var/run/openvswitch/db.sock",
		checkFunc:  checkFunc,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the unique identifier for this health checker.
func (c *OVSChecker) Name() string {
	return c.name
}

// Check performs the health check for OVS.
func (c *OVSChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()
	health := ComponentHealth{
		Name:        c.name,
		Status:      StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	if c.checkFunc == nil {
		health.Status = StatusUnhealthy
		health.Message = "check function not configured"
		health.Duration = time.Since(start)
		return health
	}

	health.Details["socket_path"] = c.socketPath

	err := c.checkFunc(ctx)
	health.Duration = time.Since(start)

	if err != nil {
		health.Status = StatusUnhealthy
		health.Message = err.Error()
		health.Details["error"] = err.Error()
		return health
	}

	health.Status = StatusHealthy
	health.Message = "OVS is responding"
	health.Details["response_time_ms"] = float64(health.Duration.Microseconds()) / 1000.0
	return health
}

// DiskChecker checks disk space health.
type DiskChecker struct {
	name   string
	path   string
	config DiskThresholdConfig
}

// DiskCheckerOption is a functional option for configuring DiskChecker.
type DiskCheckerOption func(*DiskChecker)

// WithDiskName sets the name for the disk checker.
func WithDiskName(name string) DiskCheckerOption {
	return func(c *DiskChecker) {
		c.name = name
	}
}

// WithDiskPath sets the path to check for disk space.
func WithDiskPath(path string) DiskCheckerOption {
	return func(c *DiskChecker) {
		c.path = path
	}
}

// WithDiskThresholds sets the threshold configuration for disk checker.
func WithDiskThresholds(config DiskThresholdConfig) DiskCheckerOption {
	return func(c *DiskChecker) {
		c.config = config
	}
}

// NewDiskChecker creates a new disk space health checker.
func NewDiskChecker(opts ...DiskCheckerOption) *DiskChecker {
	c := &DiskChecker{
		name:   "disk",
		path:   "/",
		config: DefaultDiskThresholdConfig(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the unique identifier for this health checker.
func (c *DiskChecker) Name() string {
	return c.name
}

// Check performs the health check for disk space.
func (c *DiskChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()
	health := ComponentHealth{
		Name:        c.name,
		Status:      StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	health.Details["path"] = c.path

	var stat unix.Statfs_t
	if err := unix.Statfs(c.path, &stat); err != nil {
		health.Status = StatusUnhealthy
		health.Message = "failed to get disk stats"
		health.Details["error"] = err.Error()
		health.Duration = time.Since(start)
		return health
	}

	totalBytes := stat.Blocks * uint64(stat.Bsize)
	freeBytes := stat.Bfree * uint64(stat.Bsize)
	usedBytes := totalBytes - freeBytes
	usagePercent := float64(usedBytes) / float64(totalBytes) * 100

	health.Details["total_bytes"] = totalBytes
	health.Details["free_bytes"] = freeBytes
	health.Details["used_bytes"] = usedBytes
	health.Details["usage_percent"] = usagePercent
	health.Details["warning_threshold"] = c.config.UsageWarning
	health.Details["critical_threshold"] = c.config.UsageCritical

	health.Duration = time.Since(start)

	if usagePercent >= c.config.UsageCritical || freeBytes < c.config.MinFreeBytes {
		health.Status = StatusUnhealthy
		health.Message = "disk space critically low"
		return health
	}

	if usagePercent >= c.config.UsageWarning {
		health.Status = StatusDegraded
		health.Message = "disk space usage is high"
		return health
	}

	health.Status = StatusHealthy
	health.Message = "disk space is adequate"
	return health
}

// MemoryChecker checks memory usage health.
type MemoryChecker struct {
	name   string
	config MemoryThresholdConfig
}

// MemoryCheckerOption is a functional option for configuring MemoryChecker.
type MemoryCheckerOption func(*MemoryChecker)

// WithMemoryName sets the name for the memory checker.
func WithMemoryName(name string) MemoryCheckerOption {
	return func(c *MemoryChecker) {
		c.name = name
	}
}

// WithMemoryThresholds sets the threshold configuration for memory checker.
func WithMemoryThresholds(config MemoryThresholdConfig) MemoryCheckerOption {
	return func(c *MemoryChecker) {
		c.config = config
	}
}

// NewMemoryChecker creates a new memory health checker.
func NewMemoryChecker(opts ...MemoryCheckerOption) *MemoryChecker {
	c := &MemoryChecker{
		name:   "memory",
		config: DefaultMemoryThresholdConfig(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the unique identifier for this health checker.
func (c *MemoryChecker) Name() string {
	return c.name
}

// Check performs the health check for memory usage.
func (c *MemoryChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()
	health := ComponentHealth{
		Name:        c.name,
		Status:      StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// memStats.Sys is total bytes of memory obtained from OS
	// memStats.HeapInuse is bytes in in-use spans
	// memStats.HeapAlloc is bytes of allocated heap objects

	allocBytes := memStats.HeapAlloc
	sysBytes := memStats.Sys
	heapInUse := memStats.HeapInuse
	heapIdle := memStats.HeapIdle
	stackInUse := memStats.StackInuse
	numGC := memStats.NumGC
	pauseTotalNs := memStats.PauseTotalNs

	// Calculate usage based on heap allocation vs system memory
	usagePercent := float64(allocBytes) / float64(sysBytes) * 100 // nolint:mnd

	health.Details["alloc_bytes"] = allocBytes
	health.Details["sys_bytes"] = sysBytes
	health.Details["heap_in_use"] = heapInUse
	health.Details["heap_idle"] = heapIdle
	health.Details["stack_in_use"] = stackInUse
	health.Details["num_gc"] = numGC
	health.Details["pause_total_ns"] = pauseTotalNs
	health.Details["usage_percent"] = usagePercent
	health.Details["warning_threshold"] = c.config.UsageWarning
	health.Details["critical_threshold"] = c.config.UsageCritical

	health.Duration = time.Since(start)

	freeBytes := sysBytes - allocBytes
	if usagePercent >= c.config.UsageCritical || freeBytes < c.config.MinFreeBytes {
		health.Status = StatusUnhealthy
		health.Message = "memory usage critically high"
		return health
	}

	if usagePercent >= c.config.UsageWarning {
		health.Status = StatusDegraded
		health.Message = "memory usage is high"
		return health
	}

	health.Status = StatusHealthy
	health.Message = "memory usage is within limits"
	return health
}

// GoroutineChecker checks goroutine count health.
type GoroutineChecker struct {
	name   string
	config GoroutineThresholdConfig
}

// GoroutineCheckerOption is a functional option for configuring GoroutineChecker.
type GoroutineCheckerOption func(*GoroutineChecker)

// WithGoroutineName sets the name for the goroutine checker.
func WithGoroutineName(name string) GoroutineCheckerOption {
	return func(c *GoroutineChecker) {
		c.name = name
	}
}

// WithGoroutineThresholds sets the threshold configuration for goroutine checker.
func WithGoroutineThresholds(config GoroutineThresholdConfig) GoroutineCheckerOption {
	return func(c *GoroutineChecker) {
		c.config = config
	}
}

// NewGoroutineChecker creates a new goroutine health checker.
func NewGoroutineChecker(opts ...GoroutineCheckerOption) *GoroutineChecker {
	c := &GoroutineChecker{
		name:   "goroutines",
		config: DefaultGoroutineThresholdConfig(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Name returns the unique identifier for this health checker.
func (c *GoroutineChecker) Name() string {
	return c.name
}

// Check performs the health check for goroutine count.
func (c *GoroutineChecker) Check(ctx context.Context) ComponentHealth {
	start := time.Now()
	health := ComponentHealth{
		Name:        c.name,
		Status:      StatusUnknown,
		LastChecked: start,
		Details:     make(map[string]any),
	}

	count := runtime.NumGoroutine()
	numCPU := runtime.NumCPU()
	gomaxprocs := runtime.GOMAXPROCS(0)

	health.Details["count"] = count
	health.Details["num_cpu"] = numCPU
	health.Details["gomaxprocs"] = gomaxprocs
	health.Details["warning_threshold"] = c.config.WarningCount
	health.Details["critical_threshold"] = c.config.CriticalCount

	health.Duration = time.Since(start)

	if count >= c.config.CriticalCount {
		health.Status = StatusUnhealthy
		health.Message = "goroutine count critically high"
		return health
	}

	if count >= c.config.WarningCount {
		health.Status = StatusDegraded
		health.Message = "goroutine count is elevated"
		return health
	}

	health.Status = StatusHealthy
	health.Message = "goroutine count is normal"
	return health
}

// CustomChecker allows creation of custom health checkers with a provided check function.
type CustomChecker struct {
	name      string
	checkFunc func(ctx context.Context) ComponentHealth
}

// NewCustomChecker creates a new custom health checker.
func NewCustomChecker(name string, checkFunc func(ctx context.Context) ComponentHealth) *CustomChecker {
	return &CustomChecker{
		name:      name,
		checkFunc: checkFunc,
	}
}

// Name returns the unique identifier for this health checker.
func (c *CustomChecker) Name() string {
	return c.name
}

// Check performs the custom health check.
func (c *CustomChecker) Check(ctx context.Context) ComponentHealth {
	if c.checkFunc == nil {
		return ComponentHealth{
			Name:        c.name,
			Status:      StatusUnhealthy,
			Message:     "check function not configured",
			LastChecked: time.Now(),
		}
	}
	return c.checkFunc(ctx)
}
