# Load Balancer

## Overview

Gateway nodes provide VIP-based ingress load balancing for services in the trusted network. The load balancer distributes traffic across healthy backend instances using configurable algorithms, with continuous health monitoring to ensure availability.

## Key Features

| Feature | Description |
|---------|-------------|
| **VIP Management** | Virtual IP addresses for service endpoints |
| **Multiple Algorithms** | Round-robin, weighted RR, least-connections, maglev |
| **Health Probes** | TCP, HTTP, and gRPC health checks |
| **NAT Support** | SNAT, DNAT, and CGNAT for IoT |
| **Session Persistence** | Source IP and cookie-based affinity |
| **HA Failover** | VIP migration between gateway nodes |

## VIP-Based Ingress Load Balancing

### VIP Architecture

```
                    Internet
                       |
                       v
              +----------------+
              |  Anycast VIP   |
              | 2602:F5BB::100 |
              +-------+--------+
                      |
         +------------+------------+
         |            |            |
    +----v----+  +----v----+  +----v----+
    | Gateway |  | Gateway |  | Gateway |
    |    #1   |  |    #2   |  |    #3   |
    +---------+  +---------+  +---------+
         |            |            |
         +------+-----+-----+------+
                |           |
           +----v----+ +----v----+
           | Backend | | Backend |
           |    A    | |    B    |
           +---------+ +---------+
```

### VIP Configuration

```go
// VIP represents a virtual IP address
type VIP struct {
    Address     netip.Addr
    Port        uint16
    Protocol    Protocol       // TCP, UDP
    ServiceName string
    Backends    []*Backend
    Algorithm   LBAlgorithm
    HealthCheck *HealthCheck
    Persistence *SessionPersistence
}

// Backend represents a load balancer target
type Backend struct {
    Address   netip.Addr
    Port      uint16
    Weight    int            // For weighted algorithms
    Status    BackendStatus  // Healthy, Unhealthy, Draining
    Metadata  map[string]string
}

type BackendStatus uint8

const (
    BackendStatusHealthy BackendStatus = iota
    BackendStatusUnhealthy
    BackendStatusDraining
)

// VIPManager handles VIP operations
type VIPManager struct {
    vips        map[netip.Addr]*VIP
    ownership   map[netip.Addr]NodeID  // Which gateway owns each VIP
    db          *quicbaas.Client
    mu          sync.RWMutex
}

// CreateVIP creates a new virtual IP
func (m *VIPManager) CreateVIP(ctx context.Context, config *VIPConfig) (*VIP, error) {
    vip := &VIP{
        Address:     config.Address,
        Port:        config.Port,
        Protocol:    config.Protocol,
        ServiceName: config.ServiceName,
        Backends:    make([]*Backend, 0),
        Algorithm:   config.Algorithm,
        HealthCheck: config.HealthCheck,
        Persistence: config.Persistence,
    }

    // Register in QuicBaaS
    key := fmt.Sprintf("sdn/lb/vips/%s", config.Address)
    value, _ := json.Marshal(vip)
    if err := m.db.Put(ctx, key, string(value)); err != nil {
        return nil, fmt.Errorf("register VIP: %w", err)
    }

    // Claim ownership
    if err := m.claimVIP(ctx, config.Address); err != nil {
        return nil, fmt.Errorf("claim VIP: %w", err)
    }

    // Configure on local interface
    if err := m.configureVIPOnInterface(vip); err != nil {
        m.releaseVIP(ctx, config.Address)
        return nil, fmt.Errorf("configure interface: %w", err)
    }

    m.mu.Lock()
    m.vips[config.Address] = vip
    m.mu.Unlock()

    return vip, nil
}
```

## Load Balancing Algorithms

### Round-Robin

Simple rotation through healthy backends:

```go
// RoundRobinBalancer distributes requests evenly
type RoundRobinBalancer struct {
    counter uint64
}

// SelectBackend picks the next backend
func (r *RoundRobinBalancer) SelectBackend(vip *VIP, src netip.AddrPort) *Backend {
    healthy := getHealthyBackends(vip)
    if len(healthy) == 0 {
        return nil
    }

    idx := atomic.AddUint64(&r.counter, 1) % uint64(len(healthy))
    return healthy[idx]
}
```

### Weighted Round-Robin

Distribution based on backend capacity:

```go
// WeightedRRBalancer respects backend weights
type WeightedRRBalancer struct {
    gcd     int
    max     int
    current int
    counter int
}

// SelectBackend picks backend based on weight
func (w *WeightedRRBalancer) SelectBackend(vip *VIP, src netip.AddrPort) *Backend {
    healthy := getHealthyBackends(vip)
    if len(healthy) == 0 {
        return nil
    }

    // Calculate GCD and max weight
    if w.gcd == 0 {
        w.calculateWeightParams(healthy)
    }

    for {
        w.counter = (w.counter + 1) % len(healthy)
        if w.counter == 0 {
            w.current -= w.gcd
            if w.current <= 0 {
                w.current = w.max
            }
        }

        if healthy[w.counter].Weight >= w.current {
            return healthy[w.counter]
        }
    }
}
```

### Least Connections

Route to backend with fewest active connections:

```go
// LeastConnBalancer selects least loaded backend
type LeastConnBalancer struct {
    connections map[netip.Addr]*atomic.Int64
    mu          sync.RWMutex
}

// SelectBackend picks backend with fewest connections
func (l *LeastConnBalancer) SelectBackend(vip *VIP, src netip.AddrPort) *Backend {
    healthy := getHealthyBackends(vip)
    if len(healthy) == 0 {
        return nil
    }

    l.mu.RLock()
    defer l.mu.RUnlock()

    var selected *Backend
    minConn := int64(math.MaxInt64)

    for _, b := range healthy {
        conn := l.connections[b.Address].Load()
        // Weight-adjusted: effective_conn = actual_conn / weight
        effectiveConn := conn * 100 / int64(b.Weight)

        if effectiveConn < minConn {
            minConn = effectiveConn
            selected = b
        }
    }

    return selected
}

// IncrementConnections records new connection
func (l *LeastConnBalancer) IncrementConnections(backend netip.Addr) {
    l.mu.Lock()
    if _, ok := l.connections[backend]; !ok {
        l.connections[backend] = &atomic.Int64{}
    }
    l.mu.Unlock()

    l.connections[backend].Add(1)
}

// DecrementConnections records connection close
func (l *LeastConnBalancer) DecrementConnections(backend netip.Addr) {
    if counter, ok := l.connections[backend]; ok {
        counter.Add(-1)
    }
}
```

### Maglev Consistent Hashing

Google's consistent hashing for minimal disruption on backend changes:

```go
// MaglevBalancer implements Maglev consistent hashing
type MaglevBalancer struct {
    lookupTable []int         // Precomputed lookup table
    tableSize   int           // Prime number (65537)
    backends    []*Backend
    mu          sync.RWMutex
}

const MaglevTableSize = 65537 // Prime number

// SelectBackend uses Maglev hash for consistency
func (m *MaglevBalancer) SelectBackend(vip *VIP, src netip.AddrPort) *Backend {
    m.mu.RLock()
    defer m.mu.RUnlock()

    if len(m.backends) == 0 {
        return nil
    }

    // Hash the source for consistent mapping
    hash := m.hashSource(src)
    idx := hash % uint64(m.tableSize)

    backendIdx := m.lookupTable[idx]
    if backendIdx < 0 || backendIdx >= len(m.backends) {
        return nil
    }

    backend := m.backends[backendIdx]
    if backend.Status != BackendStatusHealthy {
        // Find next healthy in table
        return m.findNextHealthy(idx)
    }

    return backend
}

// RebuildTable rebuilds lookup table on backend changes
func (m *MaglevBalancer) RebuildTable(backends []*Backend) {
    m.mu.Lock()
    defer m.mu.Unlock()

    m.backends = backends
    m.lookupTable = make([]int, m.tableSize)

    // Initialize with -1
    for i := range m.lookupTable {
        m.lookupTable[i] = -1
    }

    if len(backends) == 0 {
        return
    }

    // Calculate permutation for each backend
    permutations := make([][]int, len(backends))
    for i, b := range backends {
        permutations[i] = m.generatePermutation(b)
    }

    // Populate lookup table
    next := make([]int, len(backends))
    filled := 0

    for filled < m.tableSize {
        for i := range backends {
            for {
                c := permutations[i][next[i]]
                next[i]++
                if m.lookupTable[c] == -1 {
                    m.lookupTable[c] = i
                    filled++
                    break
                }
            }
        }
    }
}

// generatePermutation creates permutation sequence for backend
func (m *MaglevBalancer) generatePermutation(b *Backend) []int {
    h1 := xxhash.Sum64String(b.Address.String())
    h2 := xxhash.Sum64String(b.Address.String() + ":offset")

    offset := h1 % uint64(m.tableSize)
    skip := (h2 % uint64(m.tableSize-1)) + 1

    perm := make([]int, m.tableSize)
    for i := 0; i < m.tableSize; i++ {
        perm[i] = int((offset + uint64(i)*skip) % uint64(m.tableSize))
    }

    return perm
}
```

## Backend Health Probes

### Health Check Types

| Type | Protocol | Description |
|------|----------|-------------|
| **TCP** | L4 | Connection establishment check |
| **HTTP** | L7 | HTTP GET with status code validation |
| **gRPC** | L7 | gRPC health check protocol |

### Health Check Configuration

```go
// HealthCheck defines backend health monitoring
type HealthCheck struct {
    Type              HealthCheckType
    Interval          time.Duration  // Check interval
    Timeout           time.Duration  // Single check timeout
    HealthyThreshold  int            // Checks before marking healthy
    UnhealthyThreshold int           // Checks before marking unhealthy

    // HTTP-specific
    HTTPPath          string
    HTTPExpectedCodes []int
    HTTPHost          string

    // gRPC-specific
    GRPCService       string
}

type HealthCheckType uint8

const (
    HealthCheckTypeTCP HealthCheckType = iota
    HealthCheckTypeHTTP
    HealthCheckTypeGRPC
)
```

### TCP Health Probe

```go
// TCPHealthChecker performs TCP connection checks
type TCPHealthChecker struct {
    timeout time.Duration
}

// Check verifies TCP connectivity
func (t *TCPHealthChecker) Check(ctx context.Context, backend *Backend) HealthCheckResult {
    addr := fmt.Sprintf("[%s]:%d", backend.Address, backend.Port)

    conn, err := net.DialTimeout("tcp", addr, t.timeout)
    if err != nil {
        return HealthCheckResult{
            Status:  HealthCheckFailed,
            Latency: t.timeout,
            Error:   err.Error(),
        }
    }
    defer conn.Close()

    return HealthCheckResult{
        Status:  HealthCheckPassed,
        Latency: time.Since(time.Now()),
    }
}
```

### HTTP Health Probe

```go
// HTTPHealthChecker performs HTTP health checks
type HTTPHealthChecker struct {
    client *http.Client
    config *HealthCheck
}

// Check verifies HTTP endpoint health
func (h *HTTPHealthChecker) Check(ctx context.Context, backend *Backend) HealthCheckResult {
    url := fmt.Sprintf("http://[%s]:%d%s", backend.Address, backend.Port, h.config.HTTPPath)

    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    if h.config.HTTPHost != "" {
        req.Host = h.config.HTTPHost
    }

    start := time.Now()
    resp, err := h.client.Do(req)
    latency := time.Since(start)

    if err != nil {
        return HealthCheckResult{
            Status:  HealthCheckFailed,
            Latency: latency,
            Error:   err.Error(),
        }
    }
    defer resp.Body.Close()

    // Check status code
    expectedCodes := h.config.HTTPExpectedCodes
    if len(expectedCodes) == 0 {
        expectedCodes = []int{200}
    }

    for _, code := range expectedCodes {
        if resp.StatusCode == code {
            return HealthCheckResult{
                Status:     HealthCheckPassed,
                Latency:    latency,
                StatusCode: resp.StatusCode,
            }
        }
    }

    return HealthCheckResult{
        Status:     HealthCheckFailed,
        Latency:    latency,
        StatusCode: resp.StatusCode,
        Error:      fmt.Sprintf("unexpected status code: %d", resp.StatusCode),
    }
}
```

### gRPC Health Probe

```go
// GRPCHealthChecker performs gRPC health checks
type GRPCHealthChecker struct {
    timeout time.Duration
    config  *HealthCheck
}

// Check verifies gRPC service health
func (g *GRPCHealthChecker) Check(ctx context.Context, backend *Backend) HealthCheckResult {
    addr := fmt.Sprintf("[%s]:%d", backend.Address, backend.Port)

    ctx, cancel := context.WithTimeout(ctx, g.timeout)
    defer cancel()

    conn, err := grpc.DialContext(ctx, addr,
        grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
            MinVersion: tls.VersionTLS13,
            RootCAs:    g.caCertPool,
        })),
        grpc.WithBlock(),
    )
    if err != nil {
        return HealthCheckResult{
            Status: HealthCheckFailed,
            Error:  err.Error(),
        }
    }
    defer conn.Close()

    client := healthpb.NewHealthClient(conn)

    req := &healthpb.HealthCheckRequest{
        Service: g.config.GRPCService,
    }

    start := time.Now()
    resp, err := client.Check(ctx, req)
    latency := time.Since(start)

    if err != nil {
        return HealthCheckResult{
            Status:  HealthCheckFailed,
            Latency: latency,
            Error:   err.Error(),
        }
    }

    if resp.Status == healthpb.HealthCheckResponse_SERVING {
        return HealthCheckResult{
            Status:  HealthCheckPassed,
            Latency: latency,
        }
    }

    return HealthCheckResult{
        Status:  HealthCheckFailed,
        Latency: latency,
        Error:   fmt.Sprintf("not serving: %s", resp.Status),
    }
}
```

### Health Monitor

```go
// HealthMonitor continuously monitors backend health
type HealthMonitor struct {
    vips     map[netip.Addr]*VIP
    checkers map[HealthCheckType]HealthChecker
    results  map[string]*BackendHealthState
    mu       sync.RWMutex
}

type BackendHealthState struct {
    Backend            *Backend
    LastCheck          time.Time
    LastResult         HealthCheckResult
    ConsecutiveSuccess int
    ConsecutiveFailure int
}

// Monitor runs continuous health checks
func (h *HealthMonitor) Monitor(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            h.checkAllBackends(ctx)
        }
    }
}

func (h *HealthMonitor) checkAllBackends(ctx context.Context) {
    h.mu.RLock()
    vips := make([]*VIP, 0, len(h.vips))
    for _, vip := range h.vips {
        vips = append(vips, vip)
    }
    h.mu.RUnlock()

    for _, vip := range vips {
        if vip.HealthCheck == nil {
            continue
        }

        // Check if interval has elapsed
        for _, backend := range vip.Backends {
            state := h.getBackendState(backend)
            if time.Since(state.LastCheck) < vip.HealthCheck.Interval {
                continue
            }

            go h.checkBackend(ctx, vip, backend)
        }
    }
}

func (h *HealthMonitor) checkBackend(ctx context.Context, vip *VIP, backend *Backend) {
    checker := h.checkers[vip.HealthCheck.Type]
    result := checker.Check(ctx, backend)

    h.mu.Lock()
    state := h.results[backendKey(backend)]
    state.LastCheck = time.Now()
    state.LastResult = result

    if result.Status == HealthCheckPassed {
        state.ConsecutiveSuccess++
        state.ConsecutiveFailure = 0

        if backend.Status != BackendStatusHealthy &&
            state.ConsecutiveSuccess >= vip.HealthCheck.HealthyThreshold {
            backend.Status = BackendStatusHealthy
            slog.Info("Backend marked healthy",
                slog.String("backend", backend.Address.String()),
            )
        }
    } else {
        state.ConsecutiveFailure++
        state.ConsecutiveSuccess = 0

        if backend.Status == BackendStatusHealthy &&
            state.ConsecutiveFailure >= vip.HealthCheck.UnhealthyThreshold {
            backend.Status = BackendStatusUnhealthy
            slog.Warn("Backend marked unhealthy",
                slog.String("backend", backend.Address.String()),
                slog.String("error", result.Error),
            )
        }
    }
    h.mu.Unlock()
}
```

## NAT (Network Address Translation)

### SNAT (Source NAT)

Source NAT for egress traffic:

```go
// SNATManager handles source address translation
type SNATManager struct {
    pools     map[string]*NATPool  // Named pools
    mappings  map[string]*NATMapping
    mu        sync.RWMutex
}

type NATPool struct {
    Name      string
    Addresses []netip.Addr
    PortRange PortRange
    current   int
}

type NATMapping struct {
    OriginalSrc netip.AddrPort
    TranslatedSrc netip.AddrPort
    CreatedAt   time.Time
    LastUsed    time.Time
}

// TranslateSource performs SNAT
func (s *SNATManager) TranslateSource(src netip.AddrPort, pool string) (netip.AddrPort, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    key := src.String()

    // Check for existing mapping
    if mapping, ok := s.mappings[key]; ok {
        mapping.LastUsed = time.Now()
        return mapping.TranslatedSrc, nil
    }

    // Allocate new translation
    natPool := s.pools[pool]
    if natPool == nil {
        return netip.AddrPort{}, ErrPoolNotFound
    }

    translated, err := natPool.Allocate()
    if err != nil {
        return netip.AddrPort{}, err
    }

    s.mappings[key] = &NATMapping{
        OriginalSrc:   src,
        TranslatedSrc: translated,
        CreatedAt:     time.Now(),
        LastUsed:      time.Now(),
    }

    return translated, nil
}
```

### DNAT (Destination NAT)

Destination NAT for ingress traffic:

```go
// DNATManager handles destination address translation
type DNATManager struct {
    rules    []*DNATRule
    mu       sync.RWMutex
}

type DNATRule struct {
    Match       DNATMatch
    Destination netip.AddrPort
    Priority    int
}

type DNATMatch struct {
    DestAddr netip.Addr
    DestPort uint16
    Protocol Protocol
}

// TranslateDestination performs DNAT
func (d *DNATManager) TranslateDestination(dst netip.AddrPort, proto Protocol) (netip.AddrPort, bool) {
    d.mu.RLock()
    defer d.mu.RUnlock()

    for _, rule := range d.rules {
        if rule.Match.DestAddr == dst.Addr() &&
            rule.Match.DestPort == dst.Port() &&
            rule.Match.Protocol == proto {
            return rule.Destination, true
        }
    }

    return netip.AddrPort{}, false
}
```

### CGNAT for IoT (RFC 6598)

Carrier-grade NAT for IoT devices using shared address space:

```go
// CGNATManager implements RFC 6598 carrier-grade NAT
type CGNATManager struct {
    // RFC 6598 shared address space: 100.64.0.0/10
    sharedSpace netip.Prefix

    // Port block allocation
    portBlockSize int      // 1024 ports per block
    allocatedBlocks map[NodeID]*PortBlock

    // External addresses
    externalPool []netip.Addr

    mu sync.RWMutex
}

type PortBlock struct {
    NodeID      NodeID
    External    netip.Addr
    PortStart   uint16
    PortEnd     uint16
    AllocatedAt time.Time
}

// AllocatePortBlock assigns port block to IoT device
func (c *CGNATManager) AllocatePortBlock(nodeID NodeID) (*PortBlock, error) {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Check for existing allocation
    if block, ok := c.allocatedBlocks[nodeID]; ok {
        return block, nil
    }

    // Find available block
    block, err := c.findAvailableBlock()
    if err != nil {
        return nil, err
    }

    block.NodeID = nodeID
    block.AllocatedAt = time.Now()
    c.allocatedBlocks[nodeID] = block

    return block, nil
}

// TranslateIoTTraffic applies CGNAT for IoT egress
func (c *CGNATManager) TranslateIoTTraffic(nodeID NodeID, src netip.AddrPort) (netip.AddrPort, error) {
    block, ok := c.allocatedBlocks[nodeID]
    if !ok {
        var err error
        block, err = c.AllocatePortBlock(nodeID)
        if err != nil {
            return netip.AddrPort{}, err
        }
    }

    // Map source port to allocated range
    offset := src.Port() % uint16(c.portBlockSize)
    translatedPort := block.PortStart + offset

    return netip.AddrPortFrom(block.External, translatedPort), nil
}
```

## Session Persistence

### Source IP Affinity

```go
// SourceIPPersistence routes same source to same backend
type SourceIPPersistence struct {
    affinities map[netip.Addr]*Affinity
    timeout    time.Duration
    mu         sync.RWMutex
}

type Affinity struct {
    Backend   *Backend
    CreatedAt time.Time
    LastUsed  time.Time
}

// GetAffinity returns persistent backend for source
func (s *SourceIPPersistence) GetAffinity(src netip.Addr) *Backend {
    s.mu.RLock()
    affinity, ok := s.affinities[src]
    s.mu.RUnlock()

    if !ok {
        return nil
    }

    if time.Since(affinity.LastUsed) > s.timeout {
        s.mu.Lock()
        delete(s.affinities, src)
        s.mu.Unlock()
        return nil
    }

    affinity.LastUsed = time.Now()
    return affinity.Backend
}

// SetAffinity creates persistence for source
func (s *SourceIPPersistence) SetAffinity(src netip.Addr, backend *Backend) {
    s.mu.Lock()
    s.affinities[src] = &Affinity{
        Backend:   backend,
        CreatedAt: time.Now(),
        LastUsed:  time.Now(),
    }
    s.mu.Unlock()
}
```

## Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `lb_vips_active` | Gauge | - | Active VIP count |
| `lb_backends_total` | Gauge | vip, status | Backends by status |
| `lb_connections_active` | Gauge | vip | Active connections |
| `lb_connections_total` | Counter | vip, backend | Total connections |
| `lb_bytes_in` | Counter | vip | Bytes received |
| `lb_bytes_out` | Counter | vip | Bytes sent |
| `lb_health_checks` | Counter | vip, result | Health check results |
| `lb_backend_latency_ms` | Histogram | vip, backend | Backend response time |
| `lb_algorithm_selections` | Counter | algorithm, vip | Backend selections |
| `lb_nat_translations` | Counter | type | NAT translations |

## See Also

- [Gateway Architecture](architecture.md) - Core gateway design
- [Configuration](configuration.md) - Load balancer configuration
- [SDN Policy Engine](../policy.md) - Traffic policies
