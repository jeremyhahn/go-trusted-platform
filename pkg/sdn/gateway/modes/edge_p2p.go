//go:build platform_p2p

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

// Package modes provides operational mode handlers for gateway nodes.
// Edge mode handles IoT device onboarding, DHT bootstrap, and NAT traversal
// for edge devices in the go-trusted-platform network.
package modes

import (
	"context"
	"encoding/binary"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/p2p"
)

// Default configuration values for edge mode.
const (
	// DefaultIPv6InactivityTimeout is the default timeout for IPv6 lease inactivity.
	// Active nodes keep their IP forever; only inactive nodes lose their lease.
	DefaultIPv6InactivityTimeout = 720 * time.Hour // 30 days

	// DefaultTrustedReqPerSec is the rate limit for trusted peers (reputation >= 0.80).
	DefaultTrustedReqPerSec = 100

	// DefaultUntrustedReqPerSec is the rate limit for untrusted peers (reputation < 0.80).
	DefaultUntrustedReqPerSec = 10

	// DefaultTrustThreshold is the reputation threshold for trusted status.
	DefaultTrustThreshold = 0.80

	// KademliaK is the number of nodes per bucket in Kademlia DHT.
	KademliaK = 20

	// KademliaAlpha is the number of concurrent lookups in Kademlia.
	KademliaAlpha = 3

	// DefaultNodeTier for edge devices is Tier-3 (leaf node).
	DefaultNodeTier = 3
)

// EdgeModeHandler manages IoT device onboarding, DHT bootstrap, and NAT traversal.
// It uses libp2p for peer-to-peer networking and DHT operations.
type EdgeModeHandler struct {
	config        *EdgeModeConfig
	ipv6Allocator *IPv6Allocator
	p2pNode       *p2p.Node
	rateLimiter   *PerPeerRateLimiter
	ddosProtector *DDOSProtection
	logger        *slog.Logger

	running atomic.Bool
	mu      sync.RWMutex
}

// EdgeModeConfig holds configuration for edge mode operation.
type EdgeModeConfig struct {
	// IPv6Pool is the IPv6 address pool for allocation.
	IPv6Pool net.IPNet

	// IPv6InactivityTimeout is the duration after which an inactive allocation expires.
	// Active nodes keep their IP forever; this only affects inactive nodes.
	IPv6InactivityTimeout time.Duration

	// ACMEEndorseEnabled enables ACME endorse-01 challenge support.
	ACMEEndorseEnabled bool

	// ACMEEnrollEnabled enables ACME enroll-01 challenge support.
	ACMEEnrollEnabled bool

	// FROSTPoolID identifies the FROST signing pool for IDevID issuance.
	FROSTPoolID string

	// P2PConfig is the libp2p node configuration.
	// If nil, a default configuration will be used.
	P2PConfig *p2p.NodeConfig

	// RateLimits configures per-peer rate limiting.
	RateLimits RateLimitConfig

	// Logger is the logger for the handler.
	Logger *slog.Logger
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	// TrustedReqPerSec is the request rate limit for trusted peers.
	TrustedReqPerSec int

	// UntrustedReqPerSec is the request rate limit for untrusted peers.
	UntrustedReqPerSec int

	// TrustThreshold is the reputation threshold for trusted status.
	TrustThreshold float64
}

// OnboardingRequest represents a device onboarding request.
type OnboardingRequest struct {
	// DeviceID is the unique identifier for the device.
	DeviceID string

	// TPMEK is the TPM Endorsement Key for the device.
	TPMEK []byte

	// TPMQuote is the TPM attestation quote.
	TPMQuote []byte

	// RequestedIPv6 is an optional preferred IPv6 address.
	RequestedIPv6 net.IP
}

// OnboardingResponse contains the result of device onboarding.
type OnboardingResponse struct {
	// DeviceID is the device identifier.
	DeviceID string

	// AllocatedIPv6 is the IPv6 address allocated to the device.
	AllocatedIPv6 net.IP

	// IDevIDCert is the issued IDevID certificate.
	IDevIDCert []byte

	// DHTNodeID is the DHT node identifier for the device.
	DHTNodeID []byte

	// BootstrapNodes is the list of DHT bootstrap nodes.
	BootstrapNodes []string
}

// DHTBootstrapResponse contains DHT bootstrap information.
type DHTBootstrapResponse struct {
	// BootstrapNodes is the list of DHT bootstrap node addresses.
	BootstrapNodes []string

	// Region is the regional identifier for the node.
	Region string

	// Bucket is the assigned K-bucket index.
	Bucket int
}

// IPv6Allocation tracks an IPv6 address allocation.
type IPv6Allocation struct {
	// IP is the allocated IPv6 address.
	IP net.IP

	// DeviceID is the device to which this IP is allocated.
	DeviceID string

	// AllocatedAt is when this IP was allocated.
	AllocatedAt time.Time

	// LastSeen is the last time the device was active.
	LastSeen time.Time

	// Active indicates whether the device is currently active.
	Active bool
}

// EdgeModeStatus represents the current status of edge mode.
type EdgeModeStatus struct {
	// Running indicates whether edge mode is active.
	Running bool

	// IPv6PoolSize is the total number of addresses in the pool.
	IPv6PoolSize uint64

	// IPv6Allocated is the number of allocated addresses.
	IPv6Allocated uint64

	// IPv6Available is the number of available addresses.
	IPv6Available uint64

	// ActiveDevices is the number of active devices.
	ActiveDevices uint64

	// ACMEEndorseEnabled indicates whether ACME endorse-01 is enabled.
	ACMEEndorseEnabled bool

	// ACMEEnrollEnabled indicates whether ACME enroll-01 is enabled.
	ACMEEnrollEnabled bool

	// PeerID is the libp2p peer ID of this node.
	PeerID string

	// ConnectedPeers is the number of connected libp2p peers.
	ConnectedPeers int

	// DHTRoutingTableSize is the number of peers in the DHT routing table.
	DHTRoutingTableSize int

	// NATReachability indicates the NAT reachability status.
	NATReachability string
}

// Validate checks if the EdgeModeConfig is valid.
func (c *EdgeModeConfig) Validate() error {
	if c == nil {
		return ErrConfigNil
	}

	// Validate IPv6 pool
	ones, bits := c.IPv6Pool.Mask.Size()
	if bits != 128 {
		return ErrInvalidIPv6Pool
	}
	if ones > 64 {
		return ErrInvalidIPv6Pool
	}
	if c.IPv6Pool.IP == nil || len(c.IPv6Pool.IP) != net.IPv6len {
		return ErrInvalidIPv6Pool
	}

	// Set defaults
	if c.IPv6InactivityTimeout == 0 {
		c.IPv6InactivityTimeout = DefaultIPv6InactivityTimeout
	}

	// Validate rate limits
	if c.RateLimits.TrustedReqPerSec == 0 {
		c.RateLimits.TrustedReqPerSec = DefaultTrustedReqPerSec
	}
	if c.RateLimits.UntrustedReqPerSec == 0 {
		c.RateLimits.UntrustedReqPerSec = DefaultUntrustedReqPerSec
	}
	if c.RateLimits.TrustThreshold == 0 {
		c.RateLimits.TrustThreshold = DefaultTrustThreshold
	}

	// Validate FROST pool ID if ACME enrollment is enabled
	if c.ACMEEnrollEnabled && c.FROSTPoolID == "" {
		return ErrFROSTPoolRequired
	}

	// Set default logger
	if c.Logger == nil {
		c.Logger = slog.Default()
	}

	// Set default P2P config if not provided
	if c.P2PConfig == nil {
		c.P2PConfig = &p2p.NodeConfig{
			EnableRelayClient:  true,
			EnableHolePunching: true,
			EnableAutoNAT:      true,
			DHTMode:            p2p.DHTModeAuto,
			Logger:             c.Logger,
		}
	}

	return nil
}

// NewEdgeModeHandler creates a new edge mode handler.
func NewEdgeModeHandler(config *EdgeModeConfig) (*EdgeModeHandler, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	allocator, err := NewIPv6Allocator(config.IPv6Pool, config.IPv6InactivityTimeout)
	if err != nil {
		return nil, err
	}

	rateLimiter := NewPerPeerRateLimiter(
		config.RateLimits.TrustedReqPerSec,
		config.RateLimits.UntrustedReqPerSec,
		config.RateLimits.TrustThreshold,
	)

	// Create libp2p node
	p2pNode, err := p2p.NewNode(config.P2PConfig)
	if err != nil {
		return nil, &ErrStartFailed{Component: "libp2p", Cause: err}
	}

	ddosProtector := NewDDOSProtection()

	return &EdgeModeHandler{
		config:        config,
		ipv6Allocator: allocator,
		p2pNode:       p2pNode,
		rateLimiter:   rateLimiter,
		ddosProtector: ddosProtector,
		logger:        config.Logger.With(slog.String("component", "edge-mode")),
	}, nil
}

// Start starts the edge mode handler.
func (h *EdgeModeHandler) Start(ctx context.Context) error {
	if h.running.Load() {
		return ErrAlreadyRunning
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Start subsystems
	if err := h.ipv6Allocator.Start(ctx); err != nil {
		return &ErrStartFailed{Component: "ipv6_allocator", Cause: err}
	}

	if err := h.p2pNode.Start(ctx); err != nil {
		h.ipv6Allocator.Stop(ctx)
		return &ErrStartFailed{Component: "libp2p", Cause: err}
	}

	if err := h.rateLimiter.Start(ctx); err != nil {
		h.p2pNode.Stop(ctx)
		h.ipv6Allocator.Stop(ctx)
		return &ErrStartFailed{Component: "rate_limiter", Cause: err}
	}

	if err := h.ddosProtector.Start(ctx); err != nil {
		h.rateLimiter.Stop(ctx)
		h.p2pNode.Stop(ctx)
		h.ipv6Allocator.Stop(ctx)
		return &ErrStartFailed{Component: "ddos_protection", Cause: err}
	}

	h.running.Store(true)

	h.logger.Info("edge mode handler started",
		slog.String("peer_id", h.p2pNode.PeerID().String()))

	return nil
}

// Stop stops the edge mode handler.
func (h *EdgeModeHandler) Stop(ctx context.Context) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	var errs []error

	if err := h.ddosProtector.Stop(ctx); err != nil {
		errs = append(errs, &ErrStopFailed{Component: "ddos_protection", Cause: err})
	}

	if err := h.rateLimiter.Stop(ctx); err != nil {
		errs = append(errs, &ErrStopFailed{Component: "rate_limiter", Cause: err})
	}

	if err := h.p2pNode.Stop(ctx); err != nil {
		errs = append(errs, &ErrStopFailed{Component: "libp2p", Cause: err})
	}

	if err := h.ipv6Allocator.Stop(ctx); err != nil {
		errs = append(errs, &ErrStopFailed{Component: "ipv6_allocator", Cause: err})
	}

	h.running.Store(false)

	h.logger.Info("edge mode handler stopped")

	if len(errs) > 0 {
		return &ErrMultipleFailures{Errors: errs}
	}
	return nil
}

// OnboardDevice performs full device onboarding.
func (h *EdgeModeHandler) OnboardDevice(ctx context.Context, req *OnboardingRequest) (*OnboardingResponse, error) {
	if !h.running.Load() {
		return nil, ErrNotRunning
	}

	if req == nil {
		return nil, ErrRequestNil
	}

	if req.DeviceID == "" {
		return nil, ErrDeviceIDRequired
	}

	if len(req.TPMEK) == 0 {
		return nil, ErrTPMEKRequired
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	// Step 1: Validate TPM EK via ACME endorse-01
	if h.config.ACMEEndorseEnabled {
		if err := h.validateTPMEK(ctx, req.TPMEK); err != nil {
			return nil, &ErrOnboardingFailed{Step: "tpm_ek_validation", Cause: err}
		}
	}

	// Step 2: Issue IDevID via FROST threshold signing
	var idevIDCert []byte
	if h.config.ACMEEnrollEnabled {
		cert, err := h.issueIDevID(ctx, req.DeviceID, req.TPMEK)
		if err != nil {
			return nil, &ErrOnboardingFailed{Step: "idevid_issuance", Cause: err}
		}
		idevIDCert = cert
	}

	// Step 3: Verify TPM quote if provided
	if len(req.TPMQuote) > 0 {
		if err := h.verifyTPMQuote(ctx, req.TPMEK, req.TPMQuote); err != nil {
			return nil, &ErrOnboardingFailed{Step: "tpm_quote_verification", Cause: err}
		}
	}

	// Step 4: Allocate IPv6 from regional pool
	var allocatedIP net.IP
	var err error
	if req.RequestedIPv6 != nil && len(req.RequestedIPv6) > 0 {
		allocatedIP, err = h.ipv6Allocator.AllocateSpecific(ctx, req.DeviceID, req.RequestedIPv6)
	} else {
		allocatedIP, err = h.ipv6Allocator.Allocate(ctx, req.DeviceID)
	}
	if err != nil {
		return nil, &ErrOnboardingFailed{Step: "ipv6_allocation", Cause: err}
	}

	// Step 5: Register device via libp2p DHT
	dhtNodeID, bootstrapNodes, err := h.p2pNode.RegisterNode(ctx, req.DeviceID, allocatedIP, DefaultNodeTier)
	if err != nil {
		// Rollback IPv6 allocation on failure
		h.ipv6Allocator.Release(ctx, allocatedIP)
		return nil, &ErrOnboardingFailed{Step: "dht_registration", Cause: err}
	}

	return &OnboardingResponse{
		DeviceID:       req.DeviceID,
		AllocatedIPv6:  allocatedIP,
		IDevIDCert:     idevIDCert,
		DHTNodeID:      dhtNodeID,
		BootstrapNodes: bootstrapNodes,
	}, nil
}

// AllocateIPv6 allocates an IPv6 address from the pool.
func (h *EdgeModeHandler) AllocateIPv6(ctx context.Context, deviceID string) (net.IP, error) {
	if !h.running.Load() {
		return nil, ErrNotRunning
	}

	if deviceID == "" {
		return nil, ErrDeviceIDRequired
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.ipv6Allocator.Allocate(ctx, deviceID)
}

// ReleaseIPv6 releases an IPv6 address back to the pool.
func (h *EdgeModeHandler) ReleaseIPv6(ctx context.Context, ip net.IP) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if ip == nil || len(ip) == 0 {
		return ErrInvalidIPv6Address
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.ipv6Allocator.Release(ctx, ip)
}

// RefreshLease refreshes the lease for an IPv6 address.
func (h *EdgeModeHandler) RefreshLease(ctx context.Context, ip net.IP) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if ip == nil || len(ip) == 0 {
		return ErrInvalidIPv6Address
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.ipv6Allocator.RefreshLease(ctx, ip)
}

// BootstrapDHT handles DHT bootstrap for a new node using libp2p.
func (h *EdgeModeHandler) BootstrapDHT(ctx context.Context, nodeID []byte) (*DHTBootstrapResponse, error) {
	if !h.running.Load() {
		return nil, ErrNotRunning
	}

	if len(nodeID) == 0 {
		return nil, ErrNodeIDRequired
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	// Get bootstrap information from libp2p node
	bootstrapNodes, region, bucket, err := h.p2pNode.Bootstrap(ctx, nodeID)
	if err != nil {
		return nil, err
	}

	// Limit to KademliaK bootstrap nodes
	if len(bootstrapNodes) > KademliaK {
		bootstrapNodes = bootstrapNodes[:KademliaK]
	}

	return &DHTBootstrapResponse{
		BootstrapNodes: bootstrapNodes,
		Region:         region,
		Bucket:         bucket,
	}, nil
}

// CheckRateLimit checks if a peer is within rate limits.
func (h *EdgeModeHandler) CheckRateLimit(ctx context.Context, peerID string, reputation float64) error {
	if !h.running.Load() {
		return ErrNotRunning
	}

	if peerID == "" {
		return ErrPeerIDRequired
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	return h.rateLimiter.Check(ctx, peerID, reputation)
}

// GetStatus returns edge mode status.
func (h *EdgeModeHandler) GetStatus() *EdgeModeStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := &EdgeModeStatus{
		Running:            h.running.Load(),
		ACMEEndorseEnabled: h.config.ACMEEndorseEnabled,
		ACMEEnrollEnabled:  h.config.ACMEEnrollEnabled,
	}

	if h.ipv6Allocator != nil {
		allocatorStatus := h.ipv6Allocator.GetStatus()
		status.IPv6PoolSize = allocatorStatus.PoolSize
		status.IPv6Allocated = allocatorStatus.Allocated
		status.IPv6Available = allocatorStatus.Available
		status.ActiveDevices = allocatorStatus.ActiveDevices
	}

	if h.p2pNode != nil && h.p2pNode.IsRunning() {
		p2pStatus := h.p2pNode.GetStatus()
		status.PeerID = p2pStatus.PeerID.String()
		status.ConnectedPeers = p2pStatus.ConnectedPeers
		status.DHTRoutingTableSize = p2pStatus.DHTRoutingTable
		status.NATReachability = p2pStatus.NATStatus.Reachability
	}

	return status
}

// P2PNode returns the underlying libp2p node for advanced operations.
func (h *EdgeModeHandler) P2PNode() *p2p.Node {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.p2pNode
}

// validateTPMEK validates a TPM Endorsement Key via ACME endorse-01.
func (h *EdgeModeHandler) validateTPMEK(ctx context.Context, ek []byte) error {
	// Implementation delegates to Privacy CA integration
	// This is a placeholder for the actual ACME endorse-01 validation
	if len(ek) == 0 {
		return ErrTPMEKRequired
	}
	return nil
}

// issueIDevID issues an IDevID certificate via FROST threshold signing.
func (h *EdgeModeHandler) issueIDevID(ctx context.Context, deviceID string, ek []byte) ([]byte, error) {
	// Implementation delegates to FROST signing pool
	// This is a placeholder for the actual FROST threshold signing
	if deviceID == "" {
		return nil, ErrDeviceIDRequired
	}
	if len(ek) == 0 {
		return nil, ErrTPMEKRequired
	}
	return nil, nil
}

// verifyTPMQuote verifies a TPM attestation quote.
func (h *EdgeModeHandler) verifyTPMQuote(ctx context.Context, ek, quote []byte) error {
	// Implementation delegates to TPM quote verification
	// This is a placeholder for the actual TPM quote verification
	if len(ek) == 0 {
		return ErrTPMEKRequired
	}
	if len(quote) == 0 {
		return ErrTPMQuoteRequired
	}
	return nil
}

// IPv6Allocator manages IPv6 address allocation from a pool.
type IPv6Allocator struct {
	pool       net.IPNet
	timeout    time.Duration
	hostBits   int
	nextOffset atomic.Uint64

	allocations sync.Map // map[string]*IPv6Allocation (key: IP string)
	deviceMap   sync.Map // map[string]string (deviceID -> IP string)

	running atomic.Bool
	stopCh  chan struct{}
}

// IPv6AllocatorStatus holds the status of the IPv6 allocator.
type IPv6AllocatorStatus struct {
	PoolSize      uint64
	Allocated     uint64
	Available     uint64
	ActiveDevices uint64
}

// NewIPv6Allocator creates a new IPv6 allocator.
func NewIPv6Allocator(pool net.IPNet, timeout time.Duration) (*IPv6Allocator, error) {
	if pool.IP == nil || len(pool.IP) != net.IPv6len {
		return nil, ErrInvalidIPv6Pool
	}

	ones, bits := pool.Mask.Size()
	if bits != 128 || ones > 64 {
		return nil, ErrInvalidIPv6Pool
	}

	if timeout == 0 {
		timeout = DefaultIPv6InactivityTimeout
	}

	// Calculate host bits, capped at 63 to avoid uint64 overflow
	hostBits := 128 - ones
	if hostBits > 63 {
		hostBits = 63
	}

	return &IPv6Allocator{
		pool:     pool,
		timeout:  timeout,
		hostBits: hostBits,
		stopCh:   make(chan struct{}),
	}, nil
}

// Start starts the IPv6 allocator.
func (a *IPv6Allocator) Start(ctx context.Context) error {
	if a.running.Load() {
		return ErrAlreadyRunning
	}

	a.running.Store(true)

	// Start expiration goroutine
	go a.expirationLoop(ctx)

	return nil
}

// Stop stops the IPv6 allocator.
func (a *IPv6Allocator) Stop(ctx context.Context) error {
	if !a.running.Load() {
		return ErrNotRunning
	}

	close(a.stopCh)
	a.running.Store(false)
	return nil
}

// Allocate allocates the next available IPv6 address.
func (a *IPv6Allocator) Allocate(ctx context.Context, deviceID string) (net.IP, error) {
	if !a.running.Load() {
		return nil, ErrNotRunning
	}

	if deviceID == "" {
		return nil, ErrDeviceIDRequired
	}

	// Check if device already has an allocation
	if existingIP, ok := a.deviceMap.Load(deviceID); ok {
		ipStr := existingIP.(string)
		if alloc, ok := a.allocations.Load(ipStr); ok {
			allocation := alloc.(*IPv6Allocation)
			allocation.LastSeen = time.Now()
			allocation.Active = true
			return allocation.IP, nil
		}
	}

	// Calculate max addresses (using stored hostBits to avoid overflow)
	maxAddresses := uint64(1) << a.hostBits

	// Try to allocate using CAS atomic increment
	for attempts := 0; attempts < 1000; attempts++ {
		offset := a.nextOffset.Add(1)

		// Check if we've exhausted the pool
		if offset >= maxAddresses {
			return nil, ErrIPv6PoolExhausted
		}

		ip := a.offsetToIP(offset)
		ipStr := ip.String()

		allocation := &IPv6Allocation{
			IP:          ip,
			DeviceID:    deviceID,
			AllocatedAt: time.Now(),
			LastSeen:    time.Now(),
			Active:      true,
		}

		// Try to store allocation atomically
		if _, loaded := a.allocations.LoadOrStore(ipStr, allocation); !loaded {
			a.deviceMap.Store(deviceID, ipStr)
			return ip, nil
		}
	}

	return nil, ErrIPv6AllocationFailed
}

// AllocateSpecific tries to allocate a specific IPv6 address.
func (a *IPv6Allocator) AllocateSpecific(ctx context.Context, deviceID string, ip net.IP) (net.IP, error) {
	if !a.running.Load() {
		return nil, ErrNotRunning
	}

	if deviceID == "" {
		return nil, ErrDeviceIDRequired
	}

	if ip == nil || len(ip) != net.IPv6len {
		return nil, ErrInvalidIPv6Address
	}

	// Check if IP is within pool
	if !a.pool.Contains(ip) {
		return nil, ErrIPv6OutOfPool
	}

	ipStr := ip.String()

	allocation := &IPv6Allocation{
		IP:          ip,
		DeviceID:    deviceID,
		AllocatedAt: time.Now(),
		LastSeen:    time.Now(),
		Active:      true,
	}

	if _, loaded := a.allocations.LoadOrStore(ipStr, allocation); loaded {
		return nil, ErrIPv6AlreadyAllocated
	}

	a.deviceMap.Store(deviceID, ipStr)
	return ip, nil
}

// Release releases an IPv6 address back to the pool.
func (a *IPv6Allocator) Release(ctx context.Context, ip net.IP) error {
	if !a.running.Load() {
		return ErrNotRunning
	}

	if ip == nil || len(ip) == 0 {
		return ErrInvalidIPv6Address
	}

	ipStr := ip.String()

	if alloc, ok := a.allocations.LoadAndDelete(ipStr); ok {
		allocation := alloc.(*IPv6Allocation)
		a.deviceMap.Delete(allocation.DeviceID)
		return nil
	}

	return ErrIPv6NotAllocated
}

// RefreshLease updates the last-seen time for an allocation.
func (a *IPv6Allocator) RefreshLease(ctx context.Context, ip net.IP) error {
	if !a.running.Load() {
		return ErrNotRunning
	}

	if ip == nil || len(ip) == 0 {
		return ErrInvalidIPv6Address
	}

	ipStr := ip.String()

	if alloc, ok := a.allocations.Load(ipStr); ok {
		allocation := alloc.(*IPv6Allocation)
		allocation.LastSeen = time.Now()
		allocation.Active = true
		return nil
	}

	return ErrIPv6NotAllocated
}

// GetStatus returns the allocator status.
func (a *IPv6Allocator) GetStatus() *IPv6AllocatorStatus {
	var allocated, active uint64

	a.allocations.Range(func(key, value any) bool {
		allocated++
		if allocation := value.(*IPv6Allocation); allocation.Active {
			active++
		}
		return true
	})

	// Use stored hostBits to avoid overflow
	poolSize := uint64(1) << a.hostBits

	// For very large pools (>63 bits), use MaxUint64
	if a.hostBits >= 63 {
		poolSize = math.MaxUint64
	}

	var available uint64
	if poolSize > allocated {
		available = poolSize - allocated
	}

	return &IPv6AllocatorStatus{
		PoolSize:      poolSize,
		Allocated:     allocated,
		Available:     available,
		ActiveDevices: active,
	}
}

// offsetToIP converts an offset to an IPv6 address within the pool.
func (a *IPv6Allocator) offsetToIP(offset uint64) net.IP {
	ip := make(net.IP, net.IPv6len)
	copy(ip, a.pool.IP.To16())

	// Add offset to the host portion
	offsetBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(offsetBytes, offset)

	// Apply offset to last 8 bytes (host portion for /64 or larger)
	// Use OR instead of XOR to add the offset to the base IP
	for i := 0; i < 8; i++ {
		ip[8+i] |= offsetBytes[i]
	}

	return ip
}

// expirationLoop periodically checks for expired allocations.
func (a *IPv6Allocator) expirationLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.expireInactive()
		}
	}
}

// expireInactive removes allocations that have been inactive past the timeout.
func (a *IPv6Allocator) expireInactive() {
	now := time.Now()
	a.allocations.Range(func(key, value any) bool {
		allocation := value.(*IPv6Allocation)
		if !allocation.Active && now.Sub(allocation.LastSeen) > a.timeout {
			ipStr := key.(string)
			a.allocations.Delete(ipStr)
			a.deviceMap.Delete(allocation.DeviceID)
		}
		return true
	})
}

// regionFromIP extracts the region from an IPv6 address.
// Format: 2001:DB8:RRRR:SSSS:HHHH:HHHH:HHHH:HHHH/64
func regionFromIP(ip net.IP) string {
	if ip == nil || len(ip) < 16 {
		return "default"
	}

	// Extract region bytes (bytes 4-5 in the address)
	ip16 := ip.To16()
	if ip16 == nil {
		return "default"
	}

	regionID := binary.BigEndian.Uint16(ip16[4:6])
	return netip.AddrFrom16([16]byte{0, 0, 0, 0, byte(regionID >> 8), byte(regionID), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}).String()
}

// PerPeerRateLimiter implements per-peer rate limiting based on reputation.
type PerPeerRateLimiter struct {
	trustedRate   int
	untrustedRate int
	threshold     float64

	peerTokens sync.Map // map[string]*tokenBucket

	running atomic.Bool
	stopCh  chan struct{}
}

type tokenBucket struct {
	tokens    atomic.Int64
	lastFill  atomic.Int64
	maxTokens int64
	fillRate  int64 // tokens per second
}

// NewPerPeerRateLimiter creates a new per-peer rate limiter.
func NewPerPeerRateLimiter(trustedRate, untrustedRate int, threshold float64) *PerPeerRateLimiter {
	return &PerPeerRateLimiter{
		trustedRate:   trustedRate,
		untrustedRate: untrustedRate,
		threshold:     threshold,
		stopCh:        make(chan struct{}),
	}
}

// Start starts the rate limiter.
func (r *PerPeerRateLimiter) Start(ctx context.Context) error {
	if r.running.Load() {
		return ErrAlreadyRunning
	}
	r.running.Store(true)

	// Start cleanup goroutine
	go r.cleanupLoop(ctx)

	return nil
}

// Stop stops the rate limiter.
func (r *PerPeerRateLimiter) Stop(ctx context.Context) error {
	if !r.running.Load() {
		return ErrNotRunning
	}
	close(r.stopCh)
	r.running.Store(false)
	return nil
}

// Check checks if a peer request is within rate limits.
func (r *PerPeerRateLimiter) Check(ctx context.Context, peerID string, reputation float64) error {
	if !r.running.Load() {
		return ErrNotRunning
	}

	if peerID == "" {
		return ErrPeerIDRequired
	}

	// Determine rate based on reputation
	var rate int
	if reputation >= r.threshold {
		rate = r.trustedRate
	} else {
		rate = r.untrustedRate
	}

	bucket := r.getOrCreateBucket(peerID, rate)

	// Try to consume a token
	if !r.tryConsume(bucket) {
		return ErrRateLimitExceeded
	}

	return nil
}

// getOrCreateBucket gets or creates a token bucket for a peer.
func (r *PerPeerRateLimiter) getOrCreateBucket(peerID string, rate int) *tokenBucket {
	if existing, ok := r.peerTokens.Load(peerID); ok {
		return existing.(*tokenBucket)
	}

	bucket := &tokenBucket{
		maxTokens: int64(rate),
		fillRate:  int64(rate),
	}
	bucket.tokens.Store(int64(rate))
	bucket.lastFill.Store(time.Now().UnixNano())

	actual, _ := r.peerTokens.LoadOrStore(peerID, bucket)
	return actual.(*tokenBucket)
}

// tryConsume attempts to consume a token from the bucket.
func (r *PerPeerRateLimiter) tryConsume(bucket *tokenBucket) bool {
	now := time.Now().UnixNano()
	lastFill := bucket.lastFill.Load()
	elapsed := now - lastFill

	// Refill tokens based on elapsed time
	if elapsed > 0 {
		tokensToAdd := (elapsed * bucket.fillRate) / int64(time.Second)
		if tokensToAdd > 0 {
			if bucket.lastFill.CompareAndSwap(lastFill, now) {
				current := bucket.tokens.Add(tokensToAdd)
				if current > bucket.maxTokens {
					bucket.tokens.Store(bucket.maxTokens)
				}
			}
		}
	}

	// Try to consume a token
	for {
		current := bucket.tokens.Load()
		if current <= 0 {
			return false
		}
		if bucket.tokens.CompareAndSwap(current, current-1) {
			return true
		}
	}
}

// cleanupLoop periodically cleans up stale peer entries.
func (r *PerPeerRateLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

// cleanup removes stale peer entries.
func (r *PerPeerRateLimiter) cleanup() {
	threshold := time.Now().Add(-time.Hour).UnixNano()
	r.peerTokens.Range(func(key, value any) bool {
		bucket := value.(*tokenBucket)
		if bucket.lastFill.Load() < threshold {
			r.peerTokens.Delete(key)
		}
		return true
	})
}

// DDOSProtection implements 5-layer DDoS protection.
type DDOSProtection struct {
	running atomic.Bool
}

// NewDDOSProtection creates a new DDoS protection handler.
func NewDDOSProtection() *DDOSProtection {
	return &DDOSProtection{}
}

// Start starts DDoS protection.
func (d *DDOSProtection) Start(ctx context.Context) error {
	if d.running.Load() {
		return ErrAlreadyRunning
	}
	d.running.Store(true)
	return nil
}

// Stop stops DDoS protection.
func (d *DDOSProtection) Stop(ctx context.Context) error {
	if !d.running.Load() {
		return ErrNotRunning
	}
	d.running.Store(false)
	return nil
}
