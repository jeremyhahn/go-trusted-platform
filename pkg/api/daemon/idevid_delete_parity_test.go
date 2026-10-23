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
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
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
			assert.Zero(t, tpm.idevidCertDeletes.Load(), "%s must not delete the IDevID certificate", name)
			assert.Zero(t, tpm.iakCertDeletes.Load(), "%s must not delete the IAK certificate", name)
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

// identityCertDeleteFunc deletes the IDevID or IAK certificate over one
// transport and returns the gRPC class the transport answered with.
type identityCertDeleteFunc func(t *testing.T, key string) codes.Code

// TestIdentityCertDeleteParity drives the IDevID and IAK certificate deletes
// over every daemon transport and asserts they answer in gRPC's classes. REST
// answered every TPM error 500 and a missing TPM 503, and QUIC used its own
// error table and answered a missing TPM Unavailable; both now delegate to the
// shared IDevID service.
func TestIdentityCertDeleteParity(t *testing.T) {
	cases := []struct {
		name      string
		noTPM     bool
		deleteErr error
		want      codes.Code
	}{
		{name: "deleted", want: codes.OK},
		{name: "no certificate", deleteErr: errors.New("certificate not found"), want: codes.NotFound},
		{name: "invalid handle", deleteErr: errors.New("invalid NV index"), want: codes.InvalidArgument},
		{name: "no TPM", noTPM: true, want: codes.FailedPrecondition},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, provider, tpm := newIdentityParityFixture(t)
			tpm.deleteIDevIDCertErr = tc.deleteErr
			tpm.deleteIAKCertErr = tc.deleteErr
			if tc.noTPM {
				svc.SetTPM2Service(nil)
			}
			grpcClient, unixClient := serveIDevIDGRPC(t, svc)

			transports := map[string]identityCertDeleteFunc{
				"gRPC": grpcIdentityCertDelete(grpcClient),
				"Unix": grpcIdentityCertDelete(unixClient),
				"MCP":  mcpIdentityCertDelete(provider),
				"REST": restIdentityCertDelete(t, svc),
				"QUIC": quicIdentityCertDelete(svc),
			}
			for name, deleteCert := range transports {
				for _, key := range []string{"IDevID", "IAK"} {
					assert.Equal(t, tc.want, deleteCert(t, key), "%s %s certificate delete", name, key)
				}
			}
		})
	}
}

// tpmIAKDeleteFunc asks one transport's TPM service to delete the IAK and
// returns the gRPC class the transport's answer carries.
type tpmIAKDeleteFunc func(t *testing.T) codes.Code

// TestTPMServiceIAKDeleteParity pins #704: the TPM service's own IAK delete
// (gRPC and Unix TPMService DeleteAK, its REST route, QUIC 0x99 with
// SubOpTPM2DeleteIAK, MCP platform_tpm_iak_delete) names the same IAK the
// IDevID service refuses to delete, so each refuses with FailedPrecondition
// and none looks the IAK up, flushes a handle or deletes a certificate.
func TestTPMServiceIAKDeleteParity(t *testing.T) {
	svc, provider, tpm := newIdentityParityFixture(t)
	tpmService := NewTPMGRPCService(logging.DefaultLogger())
	tpmService.SetTPM2Service(tpm)
	grpcConn, unixConn := serveGRPCPair(t, func(server *grpc.Server) {
		platformv1.RegisterTPMServiceServer(server, tpmService)
	})

	transports := map[string]tpmIAKDeleteFunc{
		"gRPC": grpcTPMIAKDelete(platformv1.NewTPMServiceClient(grpcConn)),
		"Unix": grpcTPMIAKDelete(platformv1.NewTPMServiceClient(unixConn)),
		"MCP":  mcpTPMIAKDelete(provider),
		"REST": restTPMIAKDelete(t, tpmService),
		"QUIC": quicTPMIAKDelete(tpm, svc),
	}

	for name, deleteIAK := range transports {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.FailedPrecondition, deleteIAK(t), "%s IAK delete", name)
			assert.Zero(t, tpm.iakLookups.Load(), "%s must not look the IAK up", name)
			assert.Zero(t, tpm.flushes.Load(), "%s must not flush a TPM handle", name)
			assert.Zero(t, tpm.iakCertDeletes.Load(), "%s must not delete the IAK certificate", name)
		})
	}
}

// TestTPMServiceIAKDelete_RefusedWithoutATPM shows the refusal does not
// depend on the TPM: with none injected, gRPC and QUIC still answer
// FailedPrecondition rather than the TPM's Unavailable.
func TestTPMServiceIAKDelete_RefusedWithoutATPM(t *testing.T) {
	_, err := NewTPMGRPCService(logging.DefaultLogger()).DeleteAK(context.Background(), &platformv1.DeleteAKRequest{})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.ErrorIs(t, err, ErrDeviceIdentityKeyNotDeletable{Key: "IAK"})

	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	resp := handler.HandleRequest(context.Background(), &quicwire.Request{
		Opcode:  quicwire.OpTPM2Category,
		Payload: []byte{quicwire.SubOpTPM2DeleteIAK},
	})
	assert.Equal(t, quicwire.StatusFailedPrecondition, resp.Status)
}

func grpcTPMIAKDelete(client platformv1.TPMServiceClient) tpmIAKDeleteFunc {
	return func(t *testing.T) codes.Code {
		_, err := client.DeleteAK(context.Background(), &platformv1.DeleteAKRequest{})
		return status.Code(err)
	}
}

func mcpTPMIAKDelete(provider *MCPServiceProvider) tpmIAKDeleteFunc {
	tools := mcp.NewToolRegistry(provider, logging.DefaultLogger())
	return func(t *testing.T) codes.Code {
		_, err := tools.ExecuteTool(context.Background(), "platform_tpm_iak_delete", map[string]interface{}{})
		return status.Code(err)
	}
}

// restTPMIAKDelete drives the daemon REST TPM routes with a tpm:delete
// token; both AK paths must answer the same class.
func restTPMIAKDelete(t *testing.T, service platformv1.TPMServiceServer) tpmIAKDeleteFunc {
	key := newPTIssuerKey(t)
	validator := newSharedValidator(t, key.jwksHandler(t).URL, true)
	token := key.sign(t, "operator", "", []string{"tpm:delete"})
	server := newTPMTestRESTServer(t)
	server.SetTPMHandlers(service, tokenScopeGuard(validator))
	classify := func(httpStatus int) codes.Code {
		return classOf(httpStatus, func(c codes.Code) int {
			return idevidGRPCToHTTPStatus(status.Error(c, ""))
		})
	}
	return func(t *testing.T) codes.Code {
		byHandle := serveTPMRoute(server, http.MethodDelete, "/api/v1/tpm/ak/0x81010003", token)
		rr := serveTPMRoute(server, http.MethodDelete, "/api/v1/tpm/ak", token)
		assert.Equal(t, rr.Code, byHandle.Code, "both AK paths answer alike")
		return classify(rr.Code)
	}
}

func quicTPMIAKDelete(tpm *identityRecordingTPM, svc *IDevIDGRPCService) tpmIAKDeleteFunc {
	handler := newTestQUICServiceHandler(logging.DefaultLogger(), WithQUICTPM2Service(tpm))
	handler.SetIDevIDService(svc)
	return func(t *testing.T) codes.Code {
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{
			Opcode:  quicwire.OpTPM2Category,
			Payload: []byte{quicwire.SubOpTPM2DeleteIAK},
		})
		return classOf(resp.Status, func(c codes.Code) byte {
			return idevidGRPCToQUICStatus(status.Error(c, ""))
		})
	}
}

// serveIDevIDGRPC serves svc as serveGRPCPair does and returns a client on
// each listener.
func serveIDevIDGRPC(t *testing.T, svc platformv1.IDevIDServiceServer) (grpcClient, unixClient platformv1.IDevIDServiceClient) {
	t.Helper()
	grpcConn, unixConn := serveGRPCPair(t, func(server *grpc.Server) {
		platformv1.RegisterIDevIDServiceServer(server, svc)
	})
	return platformv1.NewIDevIDServiceClient(grpcConn), platformv1.NewIDevIDServiceClient(unixConn)
}

// serveGRPCPair serves the services register adds on a loopback TCP listener
// and on a real Unix socket, as the daemon serves its TCP and UDS gRPC
// listeners, and returns a client connection to each.
func serveGRPCPair(t *testing.T, register func(*grpc.Server)) (grpcConn, unixConn *grpc.ClientConn) {
	t.Helper()
	// The network gRPC endpoint is served over TLS on loopback, as the daemon
	// serves it; plaintext credentials are only for the Unix socket.
	tlsBundle := testutil.GenerateTestTLSBundle(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcConn = serveGRPCOn(t, register, lis, lis.Addr().String(),
		credentials.NewTLS(tlsBundle.ServerTLSConfig()), credentials.NewTLS(tlsBundle.ClientTLSConfig()))

	// A short directory keeps the socket path under the sun_path limit.
	dir, err := os.MkdirTemp("", "idevdel")
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, os.RemoveAll(dir)) })
	socket := filepath.Join(dir, "platformd.sock")
	unixLis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	unixConn = serveGRPCOn(t, register, unixLis, "unix://"+socket,
		local.NewCredentials(), local.NewCredentials())
	return grpcConn, unixConn
}

func serveGRPCOn(
	t *testing.T,
	register func(*grpc.Server),
	lis net.Listener,
	target string,
	serverCreds, clientCreds credentials.TransportCredentials,
) *grpc.ClientConn {
	t.Helper()
	server := grpc.NewServer(grpc.Creds(serverCreds))
	register(server)
	served := make(chan error, 1)
	go func() { served <- server.Serve(lis) }()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(clientCreds))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	return conn
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

func grpcIdentityCertDelete(client platformv1.IDevIDServiceClient) identityCertDeleteFunc {
	return func(t *testing.T, key string) codes.Code {
		ctx := context.Background()
		var err error
		if key == "IAK" {
			_, err = client.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})
		} else {
			_, err = client.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})
		}
		return status.Code(err)
	}
}

func mcpIdentityCertDelete(provider *MCPServiceProvider) identityCertDeleteFunc {
	return func(t *testing.T, key string) codes.Code {
		ctx := context.Background()
		if key == "IAK" {
			return status.Code(provider.IAKDeleteCert(ctx))
		}
		return status.Code(provider.IDevIDDeleteCert(ctx))
	}
}

// restIdentityCertDelete serves the REST routes with the shared service only,
// as the daemon wires it: the routes must not reach a TPM of their own.
func restIdentityCertDelete(t *testing.T, svc *IDevIDGRPCService) identityCertDeleteFunc {
	server := createTestRESTServer(t, nil)
	server.SetIDevIDService(svc)
	paths := map[string]string{"IDevID": "/api/v1/tpm/idevid/cert", "IAK": "/api/v1/tpm/iak/cert"}
	return func(t *testing.T, key string) codes.Code {
		rr := executeRESTRequest(t, server, http.MethodDelete, paths[key], nil)
		return classOf(rr.Code, func(c codes.Code) int {
			return idevidGRPCToHTTPStatus(status.Error(c, ""))
		})
	}
}

// quicIdentityCertDelete serves the QUIC opcodes with the shared service only,
// so the handler's own TPM gate is not what answers.
func quicIdentityCertDelete(svc *IDevIDGRPCService) identityCertDeleteFunc {
	handler := newTestQUICServiceHandler(logging.DefaultLogger())
	handler.SetIDevIDService(svc)
	opcodes := map[string]byte{"IDevID": quicwire.OpIDevIDDeleteCert, "IAK": quicwire.OpIAKDeleteCert}
	return func(t *testing.T, key string) codes.Code {
		resp := handler.HandleRequest(context.Background(), &quicwire.Request{Opcode: opcodes[key]})
		return classOf(resp.Status, func(c codes.Code) byte {
			return idevidGRPCToQUICStatus(status.Error(c, ""))
		})
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
