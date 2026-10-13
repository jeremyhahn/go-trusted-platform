// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// testTemplateConfigYAML is a minimal platform config a template carries;
// ToProfile parses it into the profile's config.
const testTemplateConfigYAML = "hostname: edge-01\ndomain: example.com\n"

// realTemplateServices is the production profile and template services
// over one in-memory datastore, so a profile built from a template is
// read back through the same store the template was written to.
type realTemplateServices struct {
	profiles  *device.ProfileService
	templates *device.TemplateService
}

func newRealTemplateServices(t *testing.T) realTemplateServices {
	t.Helper()
	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	ds := device.NewDatastore(storage, logging.DefaultLogger())
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)
	templates, err := device.NewTemplateService(ds)
	require.NoError(t, err)
	return realTemplateServices{profiles: profiles, templates: templates}
}

// newTemplateDeviceGRPC builds the daemon device service with the real
// template and profile services wired.
func newTemplateDeviceGRPC(t *testing.T) (*DeviceGRPCService, realTemplateServices) {
	t.Helper()
	svcs := newRealTemplateServices(t)
	return NewDeviceGRPCService(newMockDeviceService(), svcs.profiles, nil,
		WithDeviceTemplateService(svcs.templates)), svcs
}

// serveDeviceGRPC registers svc on a gRPC server over lis — the
// registration daemon.go performs for both the TCP and the Unix-socket
// server — and returns a client dialled through dial.
func serveDeviceGRPC(
	t *testing.T,
	svc platformv1.DeviceServiceServer,
	lis net.Listener,
	target string,
	serverCreds, clientCreds credentials.TransportCredentials,
	dial grpc.DialOption,
) platformv1.DeviceServiceClient {
	t.Helper()
	server := grpc.NewServer(grpc.Creds(serverCreds))
	platformv1.RegisterDeviceServiceServer(server, svc)
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})

	opts := []grpc.DialOption{grpc.WithTransportCredentials(clientCreds)}
	if dial != nil {
		opts = append(opts, dial)
	}
	conn, err := grpc.NewClient(target, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return platformv1.NewDeviceServiceClient(conn)
}

// deviceTemplateTransports are the two transports the daemon serves
// DeviceService on: gRPC (in-memory listener) and the Unix socket.
func deviceTemplateTransports(t *testing.T, svc platformv1.DeviceServiceServer) map[string]platformv1.DeviceServiceClient {
	t.Helper()

	// The network transport is TLS, as the daemon serves gRPC over TCP: the
	// self-signed test certificate is its own trust root.
	cert := testServerTLSCertificate(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	serverTLS := credentials.NewServerTLSFromCert(&cert)
	clientTLS := credentials.NewTLS(&tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13,
	})

	buf := bufconn.Listen(1 << 20)
	grpcClient := serveDeviceGRPC(t, svc, buf, "passthrough:///bufnet", serverTLS, clientTLS,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return buf.DialContext(ctx)
		}))

	// A short directory keeps the socket path under the sun_path limit.
	dir, err := os.MkdirTemp("", "devtmpl")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	unixLis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	// The Unix socket carries local credentials: the kernel vouches for the
	// peer, which is what the daemon's UDS listener relies on.
	unixClient := serveDeviceGRPC(t, svc, unixLis, "unix://"+socket,
		local.NewCredentials(), local.NewCredentials(), nil)

	return map[string]platformv1.DeviceServiceClient{
		"gRPC": grpcClient,
		"Unix": unixClient,
	}
}

func TestDeviceGRPCCreateTemplate_Transports(t *testing.T) {
	svc, svcs := newTemplateDeviceGRPC(t)
	for name, client := range deviceTemplateTransports(t, svc) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			resp, err := client.CreateTemplate(ctx, &platformv1.DeviceTemplateCreateRequest{
				Template: &platformv1.DeviceTemplate{
					TenantId:    "tenant-1",
					Name:        "edge-" + name,
					Description: "edge servers",
					Role:        platformv1.DeviceRole_DEVICE_ROLE_EDGE,
					Config:      []byte(testTemplateConfigYAML),
					MatchRules:  &platformv1.ProfileMatchRules{MacPrefix: "00:25:90"},
				},
			})
			require.NoError(t, err)
			require.True(t, resp.GetStatus().GetSuccess())

			created := resp.GetTemplate()
			require.NotZero(t, created.GetId(), "the server assigns an id")
			assert.NotNil(t, created.GetCreatedAt())

			stored, err := svcs.templates.Get(ctx, created.GetId())
			require.NoError(t, err)
			assert.Equal(t, "edge-"+name, stored.Name)
			assert.Equal(t, "tenant-1", stored.TenantID)
			assert.Equal(t, "edge servers", stored.Description)
			assert.Equal(t, entities.DeviceRoleEdge, stored.Role)
			assert.Equal(t, testTemplateConfigYAML, string(stored.Config))
			require.NotNil(t, stored.MatchRules)
			assert.Equal(t, "00:25:90", stored.MatchRules.MACPrefix)
		})
	}
}

func TestDeviceGRPCCreateTemplate_Errors(t *testing.T) {
	svc, svcs := newTemplateDeviceGRPC(t)
	bare := NewDeviceGRPCService(newMockDeviceService(), svcs.profiles, nil)

	tests := []struct {
		name string
		svc  *DeviceGRPCService
		req  *platformv1.DeviceTemplateCreateRequest
		code codes.Code
	}{
		{"missing template", svc, &platformv1.DeviceTemplateCreateRequest{}, codes.InvalidArgument},
		{"unnamed template", svc, &platformv1.DeviceTemplateCreateRequest{
			Template: &platformv1.DeviceTemplate{Role: platformv1.DeviceRole_DEVICE_ROLE_EDGE},
		}, codes.InvalidArgument},
		{"no template service", bare, &platformv1.DeviceTemplateCreateRequest{
			Template: &platformv1.DeviceTemplate{Name: "edge"},
		}, codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.svc.CreateTemplate(context.Background(), tt.req)
			assert.Equal(t, tt.code, status.Code(err), "error: %v", err)
		})
	}

	count, err := svcs.templates.Count(context.Background())
	require.NoError(t, err)
	assert.Zero(t, count, "a rejected template must not be stored")
}

func TestDeviceGRPCCreateProfileFromTemplate_Transports(t *testing.T) {
	svc, svcs := newTemplateDeviceGRPC(t)
	for name, client := range deviceTemplateTransports(t, svc) {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			tmpl, err := client.CreateTemplate(ctx, &platformv1.DeviceTemplateCreateRequest{
				Template: &platformv1.DeviceTemplate{
					Name:   "gateway-" + name,
					Role:   platformv1.DeviceRole_DEVICE_ROLE_GATEWAY,
					Config: []byte(testTemplateConfigYAML),
				},
			})
			require.NoError(t, err)

			resp, err := client.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{
				TemplateId: tmpl.GetTemplate().GetId(),
				Overrides:  &platformv1.DeviceProfile{Name: "gw-01", EkSerial: "EK-" + name},
			})
			require.NoError(t, err)
			require.True(t, resp.GetStatus().GetSuccess())
			require.NotZero(t, resp.GetProfile().GetId(), "the server assigns an id")

			stored, err := svcs.profiles.Get(ctx, resp.GetProfile().GetId())
			require.NoError(t, err)
			assert.Equal(t, "gw-01", stored.Name)
			assert.Equal(t, "EK-"+name, stored.EKSerial)
			assert.Equal(t, entities.DeviceRoleGateway, stored.Role, "role comes from the template")
			assert.Equal(t, map[string]interface{}{"hostname": "edge-01", "domain": "example.com"}, stored.Config,
				"config comes from the template")
		})
	}
}

func TestDeviceGRPCCreateProfileFromTemplate_Errors(t *testing.T) {
	svc, svcs := newTemplateDeviceGRPC(t)
	noTemplates := NewDeviceGRPCService(newMockDeviceService(), svcs.profiles, nil)
	noProfiles := NewDeviceGRPCService(newMockDeviceService(), nil, nil,
		WithDeviceTemplateService(svcs.templates))

	tests := []struct {
		name string
		svc  *DeviceGRPCService
		req  *platformv1.CreateProfileFromTemplateRequest
		code codes.Code
	}{
		{"missing template id", svc, &platformv1.CreateProfileFromTemplateRequest{}, codes.InvalidArgument},
		{"unknown template", svc, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 4242}, codes.NotFound},
		{"unparseable EK certificate override", svc, &platformv1.CreateProfileFromTemplateRequest{
			TemplateId: 4242,
			Overrides:  &platformv1.DeviceProfile{EkCert: "not a certificate"},
		}, codes.InvalidArgument},
		{"no template service", noTemplates, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 1}, codes.Unavailable},
		{"no profile service", noProfiles, &platformv1.CreateProfileFromTemplateRequest{TemplateId: 1}, codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.svc.CreateProfileFromTemplate(context.Background(), tt.req)
			assert.Equal(t, tt.code, status.Code(err), "error: %v", err)
		})
	}
}
