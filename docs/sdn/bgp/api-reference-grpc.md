# BGP gRPC API Reference

gRPC service definition for the BGP service.

| Property | Value |
|----------|-------|
| Service | `bgp.BGPService` |
| Port | 10443 |
| Transport | TCP with TLS |

## Service Definition

```protobuf
syntax = "proto3";
package bgp;

import "google/protobuf/empty.proto";
import "google/protobuf/timestamp.proto";

service BGPService {
  // Status operations
  rpc GetStatus(GetStatusRequest) returns (BGPStatus);
  rpc GetSpeakerInfo(GetSpeakerInfoRequest) returns (SpeakerInfo);

  // Peer operations
  rpc AddPeer(AddPeerRequest) returns (Peer);
  rpc GetPeer(GetPeerRequest) returns (Peer);
  rpc UpdatePeer(UpdatePeerRequest) returns (Peer);
  rpc DeletePeer(DeletePeerRequest) returns (google.protobuf.Empty);
  rpc ListPeers(ListPeersRequest) returns (ListPeersResponse);
  rpc ResetPeer(ResetPeerRequest) returns (google.protobuf.Empty);

  // Route operations
  rpc GetRoute(GetRouteRequest) returns (Route);
  rpc ListRoutes(ListRoutesRequest) returns (ListRoutesResponse);

  // EVPN operations
  rpc ListEVPNRoutes(ListEVPNRoutesRequest) returns (ListEVPNRoutesResponse);
  rpc AdvertiseMacIP(AdvertiseMacIPRequest) returns (EVPNRoute);
  rpc WithdrawMacIP(WithdrawMacIPRequest) returns (google.protobuf.Empty);
  rpc AdvertiseIPPrefix(AdvertiseIPPrefixRequest) returns (EVPNRoute);
  rpc WithdrawIPPrefix(WithdrawIPPrefixRequest) returns (google.protobuf.Empty);

  // Transit operations
  rpc ListTransitPrefixes(ListTransitPrefixesRequest) returns (ListTransitPrefixesResponse);
  rpc AnnouncePrefix(AnnouncePrefixRequest) returns (TransitPrefix);
  rpc WithdrawPrefix(WithdrawPrefixRequest) returns (google.protobuf.Empty);
  rpc BlackholePrefix(BlackholePrefixRequest) returns (TransitPrefix);

  // RPKI operations
  rpc GetRPKIStatus(GetRPKIStatusRequest) returns (RPKIStatus);
  rpc ValidatePrefix(ValidatePrefixRequest) returns (RPKIValidation);

  // Dampening operations
  rpc GetDampeningStatus(GetDampeningStatusRequest) returns (DampeningStatus);
  rpc ListSuppressedRoutes(ListSuppressedRoutesRequest) returns (ListSuppressedRoutesResponse);

  // Streaming operations
  rpc WatchPeers(WatchPeersRequest) returns (stream PeerEvent);
  rpc WatchRoutes(WatchRoutesRequest) returns (stream RouteEvent);
  rpc WatchEVPNRoutes(WatchEVPNRoutesRequest) returns (stream EVPNRouteEvent);
}
```

## Status Operations

### GetStatus

```protobuf
message GetStatusRequest {}

message BGPStatus {
  uint32 asn = 1;
  string router_id = 2;
  SpeakerRole role = 3;
  SpeakerState state = 4;
  uint64 uptime_seconds = 5;
  uint32 peer_count = 6;
  uint32 established_peers = 7;
  RouteCount route_count = 8;
  string speaker_mode = 9;
}

message RouteCount {
  uint32 ipv4_unicast = 1;
  uint32 ipv6_unicast = 2;
  uint32 l2vpn_evpn = 3;
}

enum SpeakerRole {
  SPEAKER_ROLE_UNKNOWN = 0;
  SPEAKER_ROLE_BACKBONE = 1;
  SPEAKER_ROLE_DATACENTER = 2;
  SPEAKER_ROLE_COORDINATOR = 3;
}

enum SpeakerState {
  SPEAKER_STATE_UNKNOWN = 0;
  SPEAKER_STATE_STARTING = 1;
  SPEAKER_STATE_RUNNING = 2;
  SPEAKER_STATE_STOPPING = 3;
  SPEAKER_STATE_STOPPED = 4;
}
```

**Go Example:**
```go
status, err := client.GetStatus(ctx, &bgp.GetStatusRequest{})
if err != nil {
    return err
}
fmt.Printf("BGP ASN: %d, Established Peers: %d/%d\n",
    status.Asn, status.EstablishedPeers, status.PeerCount)
```

### GetSpeakerInfo

```protobuf
message GetSpeakerInfoRequest {}

message SpeakerInfo {
  string id = 1;
  uint32 asn = 2;
  string router_id = 3;
  SpeakerRole role = 4;
  uint32 listen_port = 5;
  string vtep_ip = 6;
  repeated AddressFamily families = 7;
  SpeakerConfig config = 8;
}

message AddressFamily {
  string afi = 1;
  string safi = 2;
  bool enabled = 3;
}

message SpeakerConfig {
  uint32 hold_time = 1;
  uint32 keepalive_interval = 2;
  bool graceful_restart = 3;
  uint32 graceful_restart_time = 4;
}
```

## Peer Operations

### AddPeer

```protobuf
message AddPeerRequest {
  string address = 1;
  uint32 remote_asn = 2;
  PeerType type = 3;
  string description = 4;
  PeerConfig config = 5;
  repeated AddressFamily families = 6;
  PeerPolicies policies = 7;
}

message Peer {
  string address = 1;
  uint32 remote_asn = 2;
  PeerType type = 3;
  PeerState state = 4;
  uint64 uptime_seconds = 5;
  string description = 6;
  PeerConfig config = 7;
  repeated AddressFamily families = 8;
  PeerStatistics statistics = 9;
  PeerTimers timers = 10;
  string last_error = 11;
}

enum PeerType {
  PEER_TYPE_UNKNOWN = 0;
  PEER_TYPE_EBGP = 1;
  PEER_TYPE_IBGP = 2;
}

enum PeerState {
  PEER_STATE_UNKNOWN = 0;
  PEER_STATE_IDLE = 1;
  PEER_STATE_CONNECT = 2;
  PEER_STATE_ACTIVE = 3;
  PEER_STATE_OPENSENT = 4;
  PEER_STATE_OPENCONFIRM = 5;
  PEER_STATE_ESTABLISHED = 6;
}

message PeerConfig {
  uint32 hold_time = 1;
  uint32 keepalive_interval = 2;
  string md5_secret = 3;
  bool bfd_enabled = 4;
  bool graceful_restart = 5;
  bool multihop = 6;
  uint32 multihop_ttl = 7;
}

message PeerPolicies {
  string import_policy = 1;
  string export_policy = 2;
}

message PeerStatistics {
  uint64 messages_received = 1;
  uint64 messages_sent = 2;
  uint64 updates_received = 3;
  uint64 updates_sent = 4;
  uint64 opens_received = 5;
  uint64 opens_sent = 6;
  uint64 keepalives_received = 7;
  uint64 keepalives_sent = 8;
  uint64 notifications_received = 9;
  uint64 notifications_sent = 10;
  uint32 prefixes_received = 11;
  uint32 prefixes_sent = 12;
}

message PeerTimers {
  uint32 negotiated_hold_time = 1;
  string uptime = 2;
  google.protobuf.Timestamp last_read = 3;
  google.protobuf.Timestamp last_write = 4;
}
```

**Go Example:**
```go
peer, err := client.AddPeer(ctx, &bgp.AddPeerRequest{
    Address:     "198.51.100.1",
    RemoteAsn:   64500,
    Type:        bgp.PEER_TYPE_EBGP,
    Description: "ISP-Primary",
    Config: &bgp.PeerConfig{
        HoldTime:          90,
        KeepaliveInterval: 30,
        Md5Secret:         "bgp_secret_key",
        BfdEnabled:        true,
        GracefulRestart:   true,
    },
    Families: []*bgp.AddressFamily{
        {Afi: "ipv4", Safi: "unicast"},
        {Afi: "ipv6", Safi: "unicast"},
    },
})
```

### GetPeer

```protobuf
message GetPeerRequest {
  string address = 1;
}
```

### ListPeers

```protobuf
message ListPeersRequest {
  PeerState state = 1;
  PeerType type = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}

message ListPeersResponse {
  repeated Peer peers = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}
```

### UpdatePeer

```protobuf
message UpdatePeerRequest {
  string address = 1;
  string description = 2;
  PeerConfig config = 3;
  PeerPolicies policies = 4;
}
```

### DeletePeer

```protobuf
message DeletePeerRequest {
  string address = 1;
}
```

### ResetPeer

```protobuf
message ResetPeerRequest {
  string address = 1;
  bool soft = 2;
}
```

## Route Operations

### GetRoute

```protobuf
message GetRouteRequest {
  AddressFamily family = 1;
  string prefix = 2;
}

message Route {
  string prefix = 1;
  repeated RoutePath paths = 2;
}

message RoutePath {
  string next_hop = 1;
  Origin origin = 2;
  repeated uint32 as_path = 3;
  uint32 local_pref = 4;
  uint32 med = 5;
  repeated string communities = 6;
  bool best = 7;
  string source = 8;
  uint64 age_seconds = 9;
  RPKIValidationState rpki_status = 10;
}

enum Origin {
  ORIGIN_UNKNOWN = 0;
  ORIGIN_IGP = 1;
  ORIGIN_EGP = 2;
  ORIGIN_INCOMPLETE = 3;
}

enum RPKIValidationState {
  RPKI_STATE_UNKNOWN = 0;
  RPKI_STATE_VALID = 1;
  RPKI_STATE_INVALID = 2;
  RPKI_STATE_NOT_FOUND = 3;
}
```

### ListRoutes

```protobuf
message ListRoutesRequest {
  AddressFamily family = 1;
  string prefix = 2;
  string neighbor = 3;
  Origin origin = 4;
  bool best_only = 5;
  uint32 limit = 6;
  uint32 offset = 7;
}

message ListRoutesResponse {
  AddressFamily family = 1;
  repeated RouteEntry routes = 2;
  uint32 total = 3;
  uint32 limit = 4;
  uint32 offset = 5;
}

message RouteEntry {
  string prefix = 1;
  string next_hop = 2;
  Origin origin = 3;
  repeated uint32 as_path = 4;
  uint32 local_pref = 5;
  uint32 med = 6;
  repeated string communities = 7;
  bool best = 8;
  string source = 9;
  uint64 age_seconds = 10;
  RPKIValidationState rpki_status = 11;
}
```

**Go Example:**
```go
resp, err := client.ListRoutes(ctx, &bgp.ListRoutesRequest{
    Family:   &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
    BestOnly: true,
    Limit:    100,
})
for _, route := range resp.Routes {
    fmt.Printf("Prefix: %s, Next-Hop: %s, AS-Path: %v\n",
        route.Prefix, route.NextHop, route.AsPath)
}
```

## EVPN Operations

### ListEVPNRoutes

```protobuf
message ListEVPNRoutesRequest {
  EVPNRouteType type = 1;
  uint32 vni = 2;
  string rd = 3;
  uint32 limit = 4;
  uint32 offset = 5;
}

message ListEVPNRoutesResponse {
  repeated EVPNRoute routes = 1;
  uint32 total = 2;
  uint32 limit = 3;
  uint32 offset = 4;
}

message EVPNRoute {
  EVPNRouteType type = 1;
  string rd = 2;
  uint32 ethernet_tag = 3;
  string mac = 4;
  string ip = 5;
  uint32 vni = 6;
  string next_hop = 7;
  repeated string rt = 8;
  string prefix = 9;
  string gateway_ip = 10;
  string originator_ip = 11;
  PMSITunnel pmsi_tunnel = 12;
  string source = 13;
  uint64 age_seconds = 14;
  uint32 seq_num = 15;
}

enum EVPNRouteType {
  EVPN_TYPE_UNKNOWN = 0;
  EVPN_TYPE_2_MAC_IP = 2;
  EVPN_TYPE_3_INCLUSIVE_MULTICAST = 3;
  EVPN_TYPE_5_IP_PREFIX = 5;
}

message PMSITunnel {
  string type = 1;
  uint32 label = 2;
  string tunnel_id = 3;
}
```

### AdvertiseMacIP

```protobuf
message AdvertiseMacIPRequest {
  string mac = 1;
  string ip = 2;
  uint32 vni = 3;
  uint32 ethernet_tag = 4;
}
```

**Go Example:**
```go
route, err := client.AdvertiseMacIP(ctx, &bgp.AdvertiseMacIPRequest{
    Mac: "aa:bb:cc:dd:ee:ff",
    Ip:  "192.168.100.10",
    Vni: 1000100,
})
```

### WithdrawMacIP

```protobuf
message WithdrawMacIPRequest {
  string mac = 1;
  uint32 vni = 2;
}
```

### AdvertiseIPPrefix

```protobuf
message AdvertiseIPPrefixRequest {
  string prefix = 1;
  uint32 l3_vni = 2;
  string gateway_ip = 3;
}
```

**Go Example:**
```go
route, err := client.AdvertiseIPPrefix(ctx, &bgp.AdvertiseIPPrefixRequest{
    Prefix:    "192.168.1.0/24",
    L3Vni:     10000,
    GatewayIp: "10.0.0.1",
})
```

### WithdrawIPPrefix

```protobuf
message WithdrawIPPrefixRequest {
  string prefix = 1;
  uint32 l3_vni = 2;
}
```

## Transit Operations

### ListTransitPrefixes

```protobuf
message ListTransitPrefixesRequest {
  bool announced_only = 1;
  AddressFamily family = 2;
}

message ListTransitPrefixesResponse {
  repeated TransitPrefix prefixes = 1;
  uint32 total = 2;
}

message TransitPrefix {
  string prefix = 1;
  AddressFamily family = 2;
  bool announced = 3;
  bool signed = 4;
  uint32 signature_count = 5;
  RPKIValidationState rpki_status = 6;
  repeated string communities = 7;
  google.protobuf.Timestamp last_announced = 8;
}
```

### AnnouncePrefix

```protobuf
message AnnouncePrefixRequest {
  string prefix = 1;
  string next_hop = 2;
  repeated string communities = 3;
  bool require_signing = 4;
}
```

**Go Example:**
```go
transit, err := client.AnnouncePrefix(ctx, &bgp.AnnouncePrefixRequest{
    Prefix:         "2602:F5BB:0001::/48",
    NextHop:        "2602:F5BB:0001::1",
    Communities:    []string{"65001:300"},
    RequireSigning: true,
})
```

### WithdrawPrefix

```protobuf
message WithdrawPrefixRequest {
  string prefix = 1;
}
```

### BlackholePrefix

```protobuf
message BlackholePrefixRequest {
  string prefix = 1;
  string reason = 2;
}
```

## RPKI Operations

### GetRPKIStatus

```protobuf
message GetRPKIStatusRequest {}

message RPKIStatus {
  bool enabled = 1;
  repeated RPKIServer servers = 2;
  RPKIPolicy policy = 3;
  RPKIStatistics statistics = 4;
}

message RPKIServer {
  string address = 1;
  string state = 2;
  uint32 serial = 3;
  uint32 records = 4;
  google.protobuf.Timestamp last_sync = 5;
}

message RPKIPolicy {
  string valid_action = 1;
  string invalid_action = 2;
  string not_found_action = 3;
}

message RPKIStatistics {
  uint32 valid_routes = 1;
  uint32 invalid_routes = 2;
  uint32 not_found_routes = 3;
}
```

### ValidatePrefix

```protobuf
message ValidatePrefixRequest {
  string prefix = 1;
  uint32 asn = 2;
}

message RPKIValidation {
  string prefix = 1;
  uint32 asn = 2;
  RPKIValidationState status = 3;
  repeated ROA roas = 4;
}

message ROA {
  string prefix = 1;
  uint32 max_length = 2;
  uint32 asn = 3;
  string source = 4;
}
```

**Go Example:**
```go
validation, err := client.ValidatePrefix(ctx, &bgp.ValidatePrefixRequest{
    Prefix: "2602:F5BB::/36",
    Asn:    65001,
})
fmt.Printf("RPKI Status: %s\n", validation.Status)
```

## Dampening Operations

### GetDampeningStatus

```protobuf
message GetDampeningStatusRequest {}

message DampeningStatus {
  bool enabled = 1;
  DampeningConfig config = 2;
  uint32 suppressed_routes = 3;
  uint32 history_paths = 4;
}

message DampeningConfig {
  uint32 half_life_seconds = 1;
  uint32 suppress_threshold = 2;
  uint32 reuse_threshold = 3;
  uint32 max_suppress_seconds = 4;
}
```

### ListSuppressedRoutes

```protobuf
message ListSuppressedRoutesRequest {}

message ListSuppressedRoutesResponse {
  repeated SuppressedRoute routes = 1;
  uint32 total = 2;
}

message SuppressedRoute {
  string prefix = 1;
  uint32 penalty = 2;
  uint32 flap_count = 3;
  google.protobuf.Timestamp suppressed_since = 4;
  google.protobuf.Timestamp reuse_time = 5;
}
```

## Streaming Operations

### WatchPeers

Monitor BGP peer state changes.

```protobuf
message WatchPeersRequest {
  bool include_initial = 1;
}

message PeerEvent {
  PeerEventType type = 1;
  Peer peer = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum PeerEventType {
  PEER_EVENT_UNKNOWN = 0;
  PEER_EVENT_ADDED = 1;
  PEER_EVENT_ESTABLISHED = 2;
  PEER_EVENT_DOWN = 3;
  PEER_EVENT_REMOVED = 4;
  PEER_EVENT_STATE_CHANGE = 5;
}
```

**Go Example:**
```go
stream, err := client.WatchPeers(ctx, &bgp.WatchPeersRequest{
    IncludeInitial: true,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err != nil {
        return err
    }

    switch event.Type {
    case bgp.PEER_EVENT_ESTABLISHED:
        log.Printf("Peer established: %s (AS%d)",
            event.Peer.Address, event.Peer.RemoteAsn)
    case bgp.PEER_EVENT_DOWN:
        log.Printf("Peer down: %s, error: %s",
            event.Peer.Address, event.Peer.LastError)
    }
}
```

### WatchRoutes

Monitor route updates.

```protobuf
message WatchRoutesRequest {
  AddressFamily family = 1;
  string prefix = 2;
  bool include_initial = 3;
}

message RouteEvent {
  RouteEventType type = 1;
  RouteEntry route = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum RouteEventType {
  ROUTE_EVENT_UNKNOWN = 0;
  ROUTE_EVENT_ANNOUNCED = 1;
  ROUTE_EVENT_WITHDRAWN = 2;
  ROUTE_EVENT_UPDATED = 3;
  ROUTE_EVENT_BEST_CHANGED = 4;
}
```

**Go Example:**
```go
stream, err := client.WatchRoutes(ctx, &bgp.WatchRoutesRequest{
    Family:         &bgp.AddressFamily{Afi: "ipv6", Safi: "unicast"},
    IncludeInitial: false,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err != nil {
        return err
    }

    switch event.Type {
    case bgp.ROUTE_EVENT_ANNOUNCED:
        log.Printf("Route announced: %s via %s",
            event.Route.Prefix, event.Route.NextHop)
    case bgp.ROUTE_EVENT_WITHDRAWN:
        log.Printf("Route withdrawn: %s", event.Route.Prefix)
    }
}
```

### WatchEVPNRoutes

Monitor EVPN route updates.

```protobuf
message WatchEVPNRoutesRequest {
  EVPNRouteType type = 1;
  uint32 vni = 2;
  bool include_initial = 3;
}

message EVPNRouteEvent {
  EVPNRouteEventType type = 1;
  EVPNRoute route = 2;
  google.protobuf.Timestamp timestamp = 3;
}

enum EVPNRouteEventType {
  EVPN_EVENT_UNKNOWN = 0;
  EVPN_EVENT_ANNOUNCED = 1;
  EVPN_EVENT_WITHDRAWN = 2;
  EVPN_EVENT_MAC_MOVE = 3;
}
```

**Go Example:**
```go
stream, err := client.WatchEVPNRoutes(ctx, &bgp.WatchEVPNRoutesRequest{
    Type:           bgp.EVPN_TYPE_2_MAC_IP,
    Vni:            1000100,
    IncludeInitial: true,
})
if err != nil {
    return err
}

for {
    event, err := stream.Recv()
    if err != nil {
        return err
    }

    switch event.Type {
    case bgp.EVPN_EVENT_ANNOUNCED:
        log.Printf("EVPN Type-2: MAC %s IP %s on VNI %d",
            event.Route.Mac, event.Route.Ip, event.Route.Vni)
    case bgp.EVPN_EVENT_MAC_MOVE:
        log.Printf("MAC moved: %s now at %s",
            event.Route.Mac, event.Route.NextHop)
    }
}
```

## Error Handling

gRPC status codes map to BGP errors:

| gRPC Code | BGP Error |
|-----------|-----------|
| `NOT_FOUND` | peer_not_found, route_not_found |
| `ALREADY_EXISTS` | peer_already_exists |
| `INVALID_ARGUMENT` | invalid_prefix, invalid_asn, invalid_community |
| `FAILED_PRECONDITION` | peer_not_established, rpki_validation_failed |
| `UNAVAILABLE` | speaker_not_running |
| `UNAUTHENTICATED` | unauthorized |
| `PERMISSION_DENIED` | forbidden |

**Go Example:**
```go
peer, err := client.GetPeer(ctx, req)
if err != nil {
    if status.Code(err) == codes.NotFound {
        // Handle peer not found
    }
    if status.Code(err) == codes.FailedPrecondition {
        // Handle peer not established
    }
}
```

## Client Setup

```go
import (
    "crypto/tls"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    bgp "github.com/jeremyhahn/go-trusted-platform/api/sdn/bgp/v1"
)

func NewBGPClient(addr string, tlsConfig *tls.Config) (bgp.BGPServiceClient, error) {
    creds := credentials.NewTLS(tlsConfig)
    conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(creds))
    if err != nil {
        return nil, err
    }
    return bgp.NewBGPServiceClient(conn), nil
}

// Usage
client, err := NewBGPClient("localhost:10443", tlsConfig)
if err != nil {
    return err
}

// Get status
status, err := client.GetStatus(ctx, &bgp.GetStatusRequest{})

// Add eBGP peer
peer, err := client.AddPeer(ctx, &bgp.AddPeerRequest{
    Address:     "198.51.100.1",
    RemoteAsn:   64500,
    Type:        bgp.PEER_TYPE_EBGP,
    Description: "ISP-Primary",
    Config: &bgp.PeerConfig{
        Md5Secret:  "secret",
        BfdEnabled: true,
    },
})

// Announce transit prefix
transit, err := client.AnnouncePrefix(ctx, &bgp.AnnouncePrefixRequest{
    Prefix:         "2602:F5BB::/36",
    NextHop:        "2602:F5BB::1",
    RequireSigning: true,
})
```

## See Also

- [REST API Reference](api-reference-rest.md)
- [Architecture](architecture.md)
- [EVPN](evpn.md)
- [Transit](transit.md)
- [Configuration](configuration.md)
