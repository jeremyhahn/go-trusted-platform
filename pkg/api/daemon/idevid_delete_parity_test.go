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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/testutil"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"
)

// identityKeyDeleteFunc asks one transport to delete the named device
// identity key ("IDevID" or "IAK") and returns the gRPC class the
// transport's answer carries.
type identityKeyDeleteFunc func(t *testing.T, key string) codes.Code

// TestIdentityKeyDeleteParity pins #304 across REST, QUIC, Unix, gRPC and
// MCP: every transport refuses an IDevID or IAK key delete with the gRPC
// class FailedPrecondition and touches no certificate, all against one
// IDevIDGRPCService and one recording TPM.
func TestIdentityKeyDeleteParity(t *testing.T) {
	svc, provider, tpm := newIdentityParityFixture(t)
	idevidCert, err := createIDevIDTestCert("IDevID Test")
	require.NoError(t, err)
	iakCert, err := createIDevIDTestCert("IAK Test")
	require.NoError(t, err)
	tpm.readIDevIDCertResult = idevidCert
	tpm.readIAKCertResult = iakCert

	grpcClient, unixClient := serveIDevIDGRPC(t, svc)

	transports := map[string]identityKeyDeleteFunc{
		"gRPC": grpcIdentityKeyDelete(grpcClient),
		"Unix": grpcIdentityKeyDelete(unixClient),
		"MCP":  mcpIdentityKeyDelete(provider),
		"REST": restIdentityKeyDelete(t, tpm),
		"QUIC": quicIdentityKeyDelete(tpm, svc),
	}

	for name, deleteKey := range transports {
		t.Run(name, func(t *testing.T) {
			for _, key := range []string{"IDevID", "IAK"} {
				assert.Equal(t, codes.FailedPrecondition, deleteKey(t, key), "%s %s key delete", name, key)
			}
			assert.Zero(t, tpm.idevidCertDeletes, "%s must not delete the IDevID certificate", name)
			assert.Zero(t, tpm.iakCertDeletes, "%s must not delete the IAK certificate", name)
		})
	}

	// The keys and their certificates are all still served afterwards.
	ctx := context.Background()
	has, err := grpcClient.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})
	require.NoError(t, err)
	assert.True(t, has.GetExists(), "IDevID key must remain")
	hasIAK, err := grpcClient.HasIAK(ctx, &platformv1.HasIAKRequest{})
	require.NoError(t, err)
	assert.True(t, hasIAK.GetExists(), "IAK must remain")
	_, err = grpcClient.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
	assert.NoError(t, err, "IDevID certificate must remain")
	_, err = grpcClient.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
	assert.NoError(t, err, "IAK certificate must remain")
}

// serveIDevIDGRPC serves svc on an in-memory gRPC listener and on a real
// Unix socket, as the daemon serves its TCP and UDS gRPC listeners.
func serveIDevIDGRPC(t *testing.T, svc platformv1.IDevIDServiceServer) (grpcClient, unixClient platformv1.IDevIDServiceClient) {
	t.Helper()
	// The network gRPC endpoint is served over TLS on loopback, as the daemon
	// serves it; plaintext credentials are only for the Unix socket.
	tlsBundle := testutil.GenerateTestTLSBundle(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcClient = serveIDevIDGRPCOn(t, svc, lis, lis.Addr().String(),
		credentials.NewTLS(tlsBundle.ServerTLSConfig()), credentials.NewTLS(tlsBundle.ClientTLSConfig()))

	// A short directory keeps the socket path under the sun_path limit.
	dir, err := os.MkdirTemp("", "idevdel")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	unixLis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	unixClient = serveIDevIDGRPCOn(t, svc, unixLis, "unix://"+socket,
		local.NewCredentials(), local.NewCredentials())
	return grpcClient, unixClient
}

func serveIDevIDGRPCOn(
	t *testing.T,
	svc platformv1.IDevIDServiceServer,
	lis net.Listener,
	target string,
	serverCreds, clientCreds credentials.TransportCredentials,
) platformv1.IDevIDServiceClient {
	t.Helper()
	server := grpc.NewServer(grpc.Creds(serverCreds))
	platformv1.RegisterIDevIDServiceServer(server, svc)
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return platformv1.NewIDevIDServiceClient(conn)
}

func grpcIdentityKeyDelete(client platformv1.IDevIDServiceClient) identityKeyDeleteFunc {
	return func(t *testing.T, key string) codes.Code {
		ctx := context.Background()
		var err error
		if key == "IAK" {
			_, err = client.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
		} else {
			_, err = client.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
		}
		return status.Code(err)
	}
}

func mcpIdentityKeyDelete(provider *MCPServiceProvider) identityKeyDeleteFunc {
	return func(t *testing.T, key string) codes.Code {
		ctx := context.Background()
		if key == "IAK" {
			return status.Code(provider.IAKDelete(ctx))
		}
		return status.Code(provider.IDevIDDelete(ctx))
	}
}

// restIdentityKeyDelete reads the class back from the HTTP status through
// the daemon's own gRPC-to-HTTP mapping for the IDevID service.
func restIdentityKeyDelete(t *testing.T, tpm *identityRecordingTPM) identityKeyDeleteFunc {
	server := createTestRESTServer(t, nil)
	server.SetTPM2Service(tpm)
	paths := map[string]string{"IDevID": "/api/v1/tpm/idevid", "IAK": "/api/v1/tpm/iak"}
	return func(t *testing.T, key string) codes.Code {
		rr := executeRESTRequest(t, server, http.MethodDelete, paths[key], nil)
		return classOf(rr.Code, func(c codes.Code) int {
			return idevidGRPCToHTTPStatus(status.Error(c, ""))
		})
	}
}

// quicIdentityKeyDelete reads the class back from the QUIC status byte
// through the daemon's own gRPC-to-QUIC mapping, and checks the wire name
// of that byte is the gRPC class name.
func quicIdentityKeyDelete(tpm *identityRecordingTPM, svc *IDevIDGRPCService) identityKeyDeleteFunc {
	handler := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICTPM2Service(tpm))
	handler.SetIDevIDService(svc)
	opcodes := map[string]byte{"IDevID": quicwire.OpIDevIDDelete, "IAK": quicwire.OpIAKDelete}
	return func(t *testing.T, key string) codes.Code {
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: opcodes[key]})
		class := classOf(resp.Status, func(c codes.Code) byte {
			return idevidGRPCToQUICStatus(status.Error(c, ""))
		})
		assert.Equal(t, class.String(), quicwire.StatusToString(resp.Status))
		return class
	}
}

// classOf inverts a gRPC-to-transport status mapping: it returns the one
// gRPC code that encodes to got, or codes.Unknown when none or several do.
func classOf[T comparable](got T, encode func(codes.Code) T) codes.Code {
	match := codes.Unknown
	found := 0
	for c := codes.OK; c <= codes.Unauthenticated; c++ {
		if encode(c) == got {
			match = c
			found++
		}
	}
	if found != 1 {
		return codes.Unknown
	}
	return match
}
