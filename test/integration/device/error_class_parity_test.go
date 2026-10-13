//go:build integration

package device

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"

	// Register every sdk/go transport so each case can select its own.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// missingDeviceID names no device on a fresh daemon.
const missingDeviceID = 999999999

// TestDeviceErrorClassParity is the #505 acceptance check: a failure has
// one class whatever transport carries it. Getting a device that does not
// exist through the SDK answers codes.NotFound over every transport — over
// MCP via the JSON-RPC code the server encodes and the SDK decodes, where
// before #505 it was InternalError.
func TestDeviceErrorClassParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	transports := []struct {
		name string
		opts []platform.Option
	}{
		{"gRPC", []platform.Option{
			platform.WithOnlyProtocol(platform.ProtocolGRPC),
			platform.WithGRPCAddr(GetGRPCEndpoint()),
			platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
		}},
		{"REST", []platform.Option{
			platform.WithOnlyProtocol(platform.ProtocolREST),
			platform.WithRESTAddr(GetRESTEndpoint()),
			platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
		}},
		{"QUIC", []platform.Option{
			platform.WithOnlyProtocol(platform.ProtocolQUIC),
			platform.WithQUICAddr(GetQUICEndpoint()),
			platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
		}},
		{"MCP", []platform.Option{
			platform.WithOnlyProtocol(platform.ProtocolMCP),
			platform.WithMCPAddr(GetMCPEndpoint()),
			platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
		}},
		{"Unix", []platform.Option{
			platform.WithOnlyProtocol(platform.ProtocolUnix),
			platform.WithUnixSocket(GetSocketPath()),
		}},
	}

	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			client, err := platform.Connect(ctx, platform.NewOptions(tr.opts...))
			if err != nil {
				t.Fatalf("connect over %s: %v", tr.name, err)
			}
			defer func() {
				if err := client.Close(); err != nil {
					t.Errorf("close %s client: %v", tr.name, err)
				}
			}()

			_, err = client.Device().GetDevice(ctx, &platformv1.GetDeviceRequest{Id: missingDeviceID})
			if err == nil {
				t.Fatalf("GetDevice(%d) over %s succeeded, want NotFound", missingDeviceID, tr.name)
			}
			if got := status.Code(err); got != codes.NotFound {
				t.Errorf("GetDevice(%d) over %s: class %s (%v), want NotFound", missingDeviceID, tr.name, got, err)
			}
		})
	}
}
