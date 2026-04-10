# SDN gRPC API Reference

Endpoint: `localhost:9443`

Requires mTLS authentication.

## Service Definition

```protobuf
service SDNService {
  // Bridge operations
  rpc CreateBridge(CreateBridgeRequest) returns (Bridge);
  rpc GetBridge(GetBridgeRequest) returns (Bridge);
  rpc DeleteBridge(DeleteBridgeRequest) returns (google.protobuf.Empty);
  rpc ListBridges(ListBridgesRequest) returns (ListBridgesResponse);

  // Port operations
  rpc AddPort(AddPortRequest) returns (Port);
  rpc DeletePort(DeletePortRequest) returns (google.protobuf.Empty);
  rpc GetPortState(GetPortStateRequest) returns (PortState);
  rpc SetPortState(SetPortStateRequest) returns (PortState);
  rpc GetPortStats(GetPortStatsRequest) returns (PortStats);

  // Flow operations
  rpc AddFlow(AddFlowRequest) returns (FlowResponse);
  rpc DeleteFlow(DeleteFlowRequest) returns (google.protobuf.Empty);
  rpc ListFlows(ListFlowsRequest) returns (ListFlowsResponse);

  // VLAN operations
  rpc CreateVLAN(CreateVLANRequest) returns (VLAN);
  rpc DeleteVLAN(DeleteVLANRequest) returns (google.protobuf.Empty);
  rpc ListVLANs(ListVLANsRequest) returns (ListVLANsResponse);

  // Policy operations
  rpc ApplyPolicy(ApplyPolicyRequest) returns (PolicyResponse);
  rpc GetPolicy(GetPolicyRequest) returns (PortPolicy);
  rpc ListPolicies(ListPoliciesRequest) returns (ListPoliciesResponse);
}
```

## Message Types

### Bridge Messages

```protobuf
message CreateBridgeRequest {
  string name = 1;
}

message GetBridgeRequest {
  string name = 1;
}

message DeleteBridgeRequest {
  string name = 1;
}

message ListBridgesRequest {}

message Bridge {
  string uuid = 1;
  string name = 2;
}

message ListBridgesResponse {
  repeated Bridge bridges = 1;
}
```

### Port Messages

```protobuf
message AddPortRequest {
  string bridge = 1;
  string name = 2;
}

message DeletePortRequest {
  string bridge = 1;
  string port = 2;
}

message GetPortStateRequest {
  string port = 1;
}

message SetPortStateRequest {
  string port = 1;
  string state = 2;  // "up" or "down"
}

message GetPortStatsRequest {
  string port = 1;
}

message Port {
  string uuid = 1;
  string name = 2;
  int64 tag = 3;
  repeated int64 trunks = 4;
  repeated string interfaces = 5;
}

message PortState {
  string port = 1;
  string state = 2;
  int32 of_port = 3;
}

message PortStats {
  string port = 1;
  uint64 rx_packets = 2;
  uint64 tx_packets = 3;
  uint64 rx_bytes = 4;
  uint64 tx_bytes = 5;
  uint64 rx_errors = 6;
  uint64 tx_errors = 7;
}
```

### Flow Messages

```protobuf
message AddFlowRequest {
  string bridge = 1;
  Flow flow = 2;
}

message DeleteFlowRequest {
  string bridge = 1;
  FlowMatch match = 2;
}

message ListFlowsRequest {
  string bridge = 1;
}

message Flow {
  int32 priority = 1;
  FlowMatch match = 2;
  repeated FlowAction actions = 3;
  uint64 cookie = 4;
  int32 idle_timeout = 5;
  int32 hard_timeout = 6;
}

message FlowMatch {
  uint32 in_port = 1;
  string eth_src = 2;
  string eth_dst = 3;
  uint32 eth_type = 4;
  uint32 vlan_vid = 5;
  uint32 ip_proto = 6;
  string ipv4_src = 7;
  string ipv4_dst = 8;
  uint32 tcp_src = 9;
  uint32 tcp_dst = 10;
  uint32 udp_src = 11;
  uint32 udp_dst = 12;
}

message FlowAction {
  string type = 1;  // "output", "set_vlan", "pop_vlan", "normal"
  uint32 port = 2;
  uint32 vlan = 3;
}

message FlowResponse {
  uint64 cookie = 1;
  int32 priority = 2;
}

message ListFlowsResponse {
  repeated FlowStats flows = 1;
}

message FlowStats {
  Flow flow = 1;
  uint64 packet_count = 2;
  uint64 byte_count = 3;
}
```

### VLAN Messages

```protobuf
message CreateVLANRequest {
  uint32 vlan_id = 1;
  string name = 2;
}

message DeleteVLANRequest {
  uint32 vlan_id = 1;
}

message ListVLANsRequest {}

message VLAN {
  uint32 vlan_id = 1;
  string name = 2;
}

message ListVLANsResponse {
  repeated VLAN vlans = 1;
}
```

### Policy Messages

```protobuf
message ApplyPolicyRequest {
  string port = 1;
  PortPolicy policy = 2;
}

message GetPolicyRequest {
  string port = 1;
}

message ListPoliciesRequest {}

message PortPolicy {
  string tenant_id = 1;
  uint32 vlan = 2;
  repeated ACLRule acls = 3;
  google.protobuf.Timestamp expires_at = 4;
  map<string, string> metadata = 5;
}

message ACLRule {
  int32 priority = 1;
  FlowMatch match = 2;
  FlowAction action = 3;
  string description = 4;
}

message PolicyResponse {
  string port = 1;
  string tenant_id = 2;
  uint32 vlan = 3;
}

message ListPoliciesResponse {
  repeated PolicyResponse policies = 1;
}
```

## Usage Examples

### Go Client

```go
import (
    "context"
    pb "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/sdn"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

// Connect with mTLS
creds, _ := credentials.NewClientTLSFromFile("ca.crt", "")
conn, _ := grpc.Dial("localhost:9443", grpc.WithTransportCredentials(creds))
client := pb.NewSDNServiceClient(conn)

// Create bridge
bridge, err := client.CreateBridge(ctx, &pb.CreateBridgeRequest{
    Name: "br0",
})

// Add port
port, err := client.AddPort(ctx, &pb.AddPortRequest{
    Bridge: "br0",
    Name:   "eth0",
})

// Add flow
resp, err := client.AddFlow(ctx, &pb.AddFlowRequest{
    Bridge: "br0",
    Flow: &pb.Flow{
        Priority: 100,
        Match: &pb.FlowMatch{
            InPort:  1,
            EthType: 0x0800,
        },
        Actions: []*pb.FlowAction{
            {Type: "output", Port: 2},
        },
    },
})

// Apply policy
policy, err := client.ApplyPolicy(ctx, &pb.ApplyPolicyRequest{
    Port: "eth0",
    Policy: &pb.PortPolicy{
        TenantId: "tenant-a",
        Vlan:     100,
    },
})
```

## Error Codes

gRPC status codes:
- `NOT_FOUND`: Resource does not exist
- `ALREADY_EXISTS`: Resource already exists
- `INVALID_ARGUMENT`: Invalid request parameters
- `INTERNAL`: Server error
- `UNAUTHENTICATED`: Missing or invalid credentials
