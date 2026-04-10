# Gateway Configuration Reference

## Overview

This document provides a complete configuration reference for unified gateway nodes, covering all three operational modes (overlay, edge, transit), cluster settings, load balancer configuration, and security options.

## Configuration Structure

```yaml
sdn:
  gateway:
    # Global gateway settings
    enabled: true
    node_id: "gw-na-east-01"

    # Mode enablement
    modes:
      overlay: true
      edge: true
      transit: false

    # Cluster coordination
    cluster:
      enabled: true
      # ...

    # Mode-specific configuration
    overlay:
      # ...

    edge:
      # ...

    transit:
      # ...

    # Load balancer configuration
    loadbalancer:
      # ...

    # Security settings
    security:
      # ...
```

## Global Settings

### Gateway Identity

```yaml
sdn:
  gateway:
    enabled: true

    # Unique gateway identifier
    node_id: "gw-na-east-01"

    # Network addresses
    underlay_ip: "10.0.0.1"
    overlay_ip: "2602:f5bb:1::1"

    # Certificate for mTLS
    certificate: "/etc/platformd/certs/gateway.crt"
    private_key: "/etc/platformd/certs/gateway.key"
    ca_bundle: "/etc/platformd/certs/ca-bundle.crt"

    # Logging
    log_level: "info"  # debug, info, warn, error
```

### Mode Enablement

```yaml
sdn:
  gateway:
    modes:
      # SDN overlay mode - VTEP, EVPN, ARP suppression
      overlay: true

      # Edge/P2P/IoT mode - ACME, DHT bootstrap, IPv6 allocation
      edge: true

      # BGP transit mode - route announcement
      transit: false
```

## Cluster Configuration

### QuicBaaS Integration

```yaml
sdn:
  gateway:
    cluster:
      enabled: true

      # QuicBaaS partition for gateway state
      quicbaas:
        partition: "sdn/gateway"
        connection: "localhost:10443"

      # Heartbeat settings (see 00-CONSTANTS.md)
      heartbeat:
        interval: 2s            # HeartbeatInterval
        missed_threshold: 4     # MissedHeartbeatThreshold
        failure_timeout: 8s     # FailureDetectionTimeout

      # VIP failover
      vip_failover:
        enabled: true
        claim_timeout: 5s
        priority_formula: "reputation * 100 + uptime_days"
```

### HA Configuration

```yaml
sdn:
  gateway:
    cluster:
      ha:
        # Active-active clustering
        mode: "active-active"

        # Minimum gateways for quorum
        min_quorum: 2

        # Session state replication
        session_replication: true

        # Graceful demotion timeout
        demotion_timeout: 30s
```

## Overlay Mode Configuration

### VTEP Settings

```yaml
sdn:
  gateway:
    overlay:
      enabled: true

      # VXLAN tunnel endpoint
      vtep:
        ip: "10.0.0.1"
        port: 4789

      # Underlay network
      underlay:
        interface: "eth0"
        mtu: 9000

      # VNI configuration
      vni:
        base: 1000000  # VNI = base + VLAN

      # EVPN BGP peering
      evpn:
        enabled: true
        asn: 65001
        router_id: "10.0.0.1"

        # Route reflector clients (iBGP)
        neighbors:
          - address: "10.0.0.2"
            remote_as: 65001
            description: "Gateway 2"
          - address: "10.0.0.3"
            remote_as: 65001
            description: "Gateway 3"
```

### ARP Suppression

```yaml
sdn:
  gateway:
    overlay:
      arp_suppression:
        enabled: true

        # Cache settings
        cache:
          max_entries: 16384
          ttl: 5m

        # Proxy ARP response
        proxy_arp: true
```

### Distributed Anycast Gateway

```yaml
sdn:
  gateway:
    overlay:
      anycast_gateway:
        enabled: true

        # Shared gateway MAC (VRRP-style)
        mac_prefix: "00:00:5e:00:01"

        # Per-VNI gateway configuration
        gateways:
          - vni: 1000100
            subnet: "10.100.0.0/24"
            gateway_ip: "10.100.0.1"
          - vni: 1000200
            subnet: "10.200.0.0/24"
            gateway_ip: "10.200.0.1"
```

### OpenFlow Pipeline

```yaml
sdn:
  gateway:
    overlay:
      openflow:
        # OVS bridge name
        bridge: "br-int"

        # Controller connection
        controller: "tcp:127.0.0.1:6653"

        # Pipeline tables
        tables:
          ingress_classification: 0
          vxlan_decap: 10
          authentication: 20
          mac_learning: 30
          arp_handling: 40
          l3_routing: 50
          egress: 60
```

## Edge Mode Configuration

### ACME Server

```yaml
sdn:
  gateway:
    edge:
      enabled: true

      acme:
        enabled: true

        # Listen address
        listen: ":8443"

        # Challenge types
        challenges:
          - endorse-01  # TPM endorsement validation
          - enroll-01   # IDevID certificate issuance

        # FROST CA integration
        frost_ca:
          endpoint: "grpc://frost-ca:10443"
          timeout: 30s

        # Session TTL
        session_ttl: 1h

        # Rate limiting
        rate_limit:
          per_ip: 10/min
          global: 1000/min
```

### DHT Bootstrap

```yaml
sdn:
  gateway:
    edge:
      dht_bootstrap:
        enabled: true

        # Listen address
        listen: ":10443"

        # Bootstrap response
        response:
          # Number of closest nodes to return
          k_closest: 20

          # Include regional coordinators
          include_coordinators: true

        # Rate limiting
        rate_limit:
          per_node: 5/min
          global: 500/min
```

### IPv6 Allocation

```yaml
sdn:
  gateway:
    edge:
      ipv6_allocation:
        enabled: true

        # Regional pool
        pool: "2602:f5bb:0001::/48"

        # Inactivity timeout (addresses are permanent until inactive)
        # Nodes keep their IP forever as long as they connect within this window
        inactivity_timeout: 720h  # 30 days - only reallocate if inactive this long

        # Allocation strategy
        strategy: "random"  # random, sequential

        # Collision handling
        max_retries: 100
```

### NAT Traversal

```yaml
sdn:
  gateway:
    edge:
      nat_traversal:
        stun:
          enabled: true
          listen: ":3478"

          # Alternative address for NAT detection
          alt_address: "10.0.0.2:3479"

        turn:
          enabled: true
          listen: ":3478"

          # Relay address range
          relay_min_port: 49152
          relay_max_port: 65535

          # Allocation limits
          max_allocations: 10000
          allocation_timeout: 10m

          # Authentication
          auth_realm: "trusted-platform"
```

### Rate Limiting

```yaml
sdn:
  gateway:
    edge:
      rate_limiting:
        enabled: true

        # Tiers based on reputation (see 00-CONSTANTS.md)
        tiers:
          trusted:       # reputation >= 0.80
            rate: 100/s
            burst: 200
          untrusted:     # reputation < 0.80
            rate: 10/s
            burst: 20
          new:           # no reputation history
            rate: 5/s
            burst: 10

        # Global limits
        global:
          rate: 10000/s
          burst: 20000
```

## Transit Mode Configuration

### BGP Speaker

```yaml
sdn:
  gateway:
    transit:
      enabled: true

      bgp:
        # Local AS number
        local_as: 65001

        # Router ID
        router_id: "10.0.0.1"

        # Address families
        families:
          - afi: ipv4
            safi: unicast
          - afi: ipv6
            safi: unicast

        # Graceful restart
        graceful_restart:
          enabled: true
          restart_time: 120s
          stale_routes_time: 360s
```

### ISP Peering

```yaml
sdn:
  gateway:
    transit:
      peers:
        # Primary ISP
        - name: "ISP-Primary"
          address: "198.51.100.1"
          remote_as: 64500
          type: ebgp

          # MD5 authentication
          md5_password: "${ISP_PRIMARY_SECRET}"

          # Timers
          hold_time: 90s
          keepalive: 30s

          # Policies
          import_policy: "import-from-isp"
          export_policy: "export-to-isp"

        # Backup ISP
        - name: "ISP-Backup"
          address: "198.51.100.2"
          remote_as: 64501
          type: ebgp
          md5_password: "${ISP_BACKUP_SECRET}"

          # AS-PATH prepending for backup
          prepend:
            enabled: true
            count: 3
```

### Route Announcements

```yaml
sdn:
  gateway:
    transit:
      announcements:
        # IPv6 aggregate
        - prefix: "2602:f5bb::/36"
          origin: igp
          communities:
            - "65001:100"  # Originated

        # IPv4 block
        - prefix: "23.143.36.0/24"
          origin: igp
          communities:
            - "65001:100"

        # Regional prefix (datacenter speakers only)
        - prefix: "2602:f5bb:0001::/48"
          origin: igp
          speaker_role: datacenter
```

### RPKI Validation

```yaml
sdn:
  gateway:
    transit:
      rpki:
        enabled: true

        # RTR servers
        servers:
          - address: "rpki-validator.example.com"
            port: 8323
            prefer: true
          - address: "rpki-backup.example.com"
            port: 8323

        # Validation policy
        policy:
          valid: accept
          invalid: reject
          not_found: accept

        # Cache settings
        cache:
          lifetime: 3600s
          refresh_interval: 300s
```

### BGP Dampening

```yaml
sdn:
  gateway:
    transit:
      dampening:
        enabled: true

        # Dampening parameters (see 00-CONSTANTS.md)
        half_life: 15m
        suppress_threshold: 2000
        reuse_threshold: 750
        max_suppress_time: 60m
```

### Route Signing

```yaml
sdn:
  gateway:
    transit:
      route_signing:
        enabled: true

        # Coordinator cluster for signatures
        coordinator_cluster:
          endpoint: "grpc://coordinator:10443"
          timeout: 10s

        # Signature requirements
        quorum: 3

        # Request rate limiting
        rate_limit: 10/min
```

## Load Balancer Configuration

### VIP Management

```yaml
sdn:
  gateway:
    loadbalancer:
      enabled: true

      # VIP configuration
      vips:
        - address: "2602:f5bb::100"
          port: 443
          protocol: tcp
          service_name: "api-gateway"

          # Algorithm
          algorithm: maglev  # round-robin, weighted-rr, least-conn, maglev

          # Backends
          backends:
            - address: "10.0.1.1"
              port: 8443
              weight: 100
            - address: "10.0.1.2"
              port: 8443
              weight: 100

          # Health check
          health_check:
            type: http
            path: "/health"
            interval: 5s
            timeout: 2s
            healthy_threshold: 2
            unhealthy_threshold: 3
            expected_codes: [200]

          # Session persistence
          persistence:
            type: source_ip
            timeout: 1h
```

### NAT Pools

```yaml
sdn:
  gateway:
    loadbalancer:
      nat:
        # SNAT pools
        snat_pools:
          - name: "egress-pool"
            addresses:
              - "23.143.36.10"
              - "23.143.36.11"
            port_range:
              start: 1024
              end: 65535

        # CGNAT for IoT
        cgnat:
          enabled: true
          shared_space: "100.64.0.0/10"
          port_block_size: 1024
          external_addresses:
            - "23.143.36.20"
            - "23.143.36.21"
```

### Health Checks

```yaml
sdn:
  gateway:
    loadbalancer:
      health:
        # Global settings
        default_interval: 10s
        default_timeout: 5s

        # Check types
        tcp:
          enabled: true

        http:
          enabled: true
          default_path: "/health"
          default_codes: [200, 204]

        grpc:
          enabled: true
          default_service: "grpc.health.v1.Health"
```

## Security Configuration

### DDoS Protection

```yaml
sdn:
  gateway:
    security:
      ddos:
        enabled: true

        # 5-layer protection
        layers:
          # L3/L4 rate limiting
          - type: rate_limit
            threshold: 100000/s
            action: drop

          # SYN flood protection
          - type: syn_proxy
            enabled: true
            threshold: 10000/s

          # Connection limiting
          - type: conn_limit
            per_source: 1000
            global: 1000000

          # Application layer
          - type: http_flood
            threshold: 1000/s
            action: captcha
```

### Rate Limiting

```yaml
sdn:
  gateway:
    security:
      rate_limiting:
        # Per-source limits
        per_source:
          trusted: 100/s      # Reputation >= 0.80
          untrusted: 10/s     # Reputation < 0.80

        # Burst allowance
        burst:
          trusted: 200
          untrusted: 20

        # Global limits
        global:
          requests: 100000/s
          connections: 500000
```

### Reputation Integration

```yaml
sdn:
  gateway:
    security:
      reputation:
        # Reputation service endpoint
        service: "grpc://reputation:10443"

        # Cache settings
        cache:
          ttl: 5m
          max_entries: 100000

        # Thresholds (from 00-CONSTANTS.md)
        thresholds:
          trusted: 0.80
          gateway_eligible: 0.85
          coordinator_eligible: 0.95
```

## Environment Variables

Environment variables can override YAML configuration:

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_NODE_ID` | - | Gateway node identifier |
| `GATEWAY_UNDERLAY_IP` | - | Underlay network IP |
| `GATEWAY_OVERLAY_IP` | - | Overlay network IP |
| `GATEWAY_LOG_LEVEL` | info | Log level |
| `GATEWAY_MODES` | overlay,edge | Enabled modes |
| `GATEWAY_QUICBAAS_ADDR` | localhost:10443 | QuicBaaS address |
| `GATEWAY_VTEP_PORT` | 4789 | VXLAN port |
| `GATEWAY_BGP_ASN` | 65001 | BGP AS number |

## Complete Example

```yaml
# /etc/platformd/gateway.yaml
sdn:
  gateway:
    enabled: true
    node_id: "gw-na-east-01"
    underlay_ip: "10.0.0.1"
    overlay_ip: "2602:f5bb:1::1"
    log_level: "info"

    certificate: "/etc/platformd/certs/gateway.crt"
    private_key: "/etc/platformd/certs/gateway.key"
    ca_bundle: "/etc/platformd/certs/ca-bundle.crt"

    modes:
      overlay: true
      edge: true
      transit: true

    cluster:
      enabled: true
      quicbaas:
        partition: "sdn/gateway"
        connection: "localhost:10443"
      heartbeat:
        interval: 2s
        missed_threshold: 4
        failure_timeout: 8s
      ha:
        mode: "active-active"
        min_quorum: 2
        session_replication: true

    overlay:
      vtep:
        ip: "10.0.0.1"
        port: 4789
      underlay:
        interface: "eth0"
        mtu: 9000
      vni:
        base: 1000000
      evpn:
        enabled: true
        asn: 65001
        router_id: "10.0.0.1"
      arp_suppression:
        enabled: true
        cache:
          max_entries: 16384
          ttl: 5m
      anycast_gateway:
        enabled: true
        mac_prefix: "00:00:5e:00:01"
      openflow:
        bridge: "br-int"
        controller: "tcp:127.0.0.1:6653"

    edge:
      acme:
        enabled: true
        listen: ":8443"
        challenges:
          - endorse-01
          - enroll-01
        frost_ca:
          endpoint: "grpc://frost-ca:10443"
          timeout: 30s
      dht_bootstrap:
        enabled: true
        listen: ":10443"
        response:
          k_closest: 20
          include_coordinators: true
      ipv6_allocation:
        enabled: true
        pool: "2602:f5bb:0001::/48"
        lease:
          duration: 720h
          renewal_window: 168h
          grace_period: 48h
      nat_traversal:
        stun:
          enabled: true
          listen: ":3478"
        turn:
          enabled: true
          listen: ":3478"
          max_allocations: 10000
      rate_limiting:
        enabled: true
        tiers:
          trusted:
            rate: 100/s
            burst: 200
          untrusted:
            rate: 10/s
            burst: 20

    transit:
      bgp:
        local_as: 65001
        router_id: "10.0.0.1"
        families:
          - afi: ipv6
            safi: unicast
          - afi: ipv4
            safi: unicast
        graceful_restart:
          enabled: true
          restart_time: 120s
      peers:
        - name: "ISP-Primary"
          address: "198.51.100.1"
          remote_as: 64500
          type: ebgp
          md5_password: "${ISP_PRIMARY_SECRET}"
          import_policy: "import-from-isp"
          export_policy: "export-to-isp"
      announcements:
        - prefix: "2602:f5bb::/36"
          origin: igp
          communities: ["65001:100"]
        - prefix: "23.143.36.0/24"
          origin: igp
          communities: ["65001:100"]
      rpki:
        enabled: true
        servers:
          - address: "rpki-validator.example.com"
            port: 8323
        policy:
          valid: accept
          invalid: reject
          not_found: accept
      dampening:
        enabled: true
        half_life: 15m
        suppress_threshold: 2000
        reuse_threshold: 750
        max_suppress_time: 60m
      route_signing:
        enabled: true
        coordinator_cluster:
          endpoint: "grpc://coordinator:10443"
        quorum: 3

    loadbalancer:
      enabled: true
      vips:
        - address: "2602:f5bb::100"
          port: 443
          protocol: tcp
          service_name: "api-gateway"
          algorithm: maglev
          backends:
            - address: "10.0.1.1"
              port: 8443
              weight: 100
            - address: "10.0.1.2"
              port: 8443
              weight: 100
          health_check:
            type: http
            path: "/health"
            interval: 5s
            timeout: 2s
            healthy_threshold: 2
            unhealthy_threshold: 3
          persistence:
            type: source_ip
            timeout: 1h
      nat:
        cgnat:
          enabled: true
          shared_space: "100.64.0.0/10"
          port_block_size: 1024

    security:
      ddos:
        enabled: true
        layers:
          - type: rate_limit
            threshold: 100000/s
            action: drop
          - type: syn_proxy
            enabled: true
          - type: conn_limit
            per_source: 1000
      rate_limiting:
        per_source:
          trusted: 100/s
          untrusted: 10/s
        burst:
          trusted: 200
          untrusted: 20
      reputation:
        service: "grpc://reputation:10443"
        cache:
          ttl: 5m
          max_entries: 100000
```

## See Also

- [Gateway Architecture](architecture.md) - Core gateway design
- [Overlay Mode](overlay-mode.md) - SDN overlay configuration
- [Edge Mode](edge-mode.md) - Edge gateway configuration
- [Transit Mode](transit-mode.md) - BGP transit configuration
- [Load Balancer](loadbalancer.md) - Load balancing features
- [00-CONSTANTS.md](../../dht/00-CONSTANTS.md) - System constants reference
