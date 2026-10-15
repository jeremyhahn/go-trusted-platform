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
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// identityRecordingTPM is the in-memory IDevID test TPM that also counts the
// certificate deletions it is asked for.
type identityRecordingTPM struct {
	*idevIDTestTPM
	idevidCertDeletes int
	iakCertDeletes    int
}

func (r *identityRecordingTPM) DeleteIDevIDCertificate() error {
	r.idevidCertDeletes++
	return r.idevIDTestTPM.DeleteIDevIDCertificate()
}

func (r *identityRecordingTPM) DeleteIAKCertificate() error {
	r.iakCertDeletes++
	return r.idevIDTestTPM.DeleteIAKCertificate()
}

// newIdentityParityFixture wires one IDevIDGRPCService over the recording TPM
// and an MCP provider that serves the same service, as the daemon does.
func newIdentityParityFixture(t *testing.T) (*IDevIDGRPCService, *MCPServiceProvider, *identityRecordingTPM) {
	t.Helper()
	svc := createIDevIDTestService(t)
	tpm := &identityRecordingTPM{idevIDTestTPM: newIDevIDTestTPM()}
	svc.SetTPM2Service(tpm)
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Logger: slog.Default()})
	provider.SetIDevIDService(svc)
	return svc, provider, tpm
}

// identityParityCase calls one operation over gRPC and over MCP against the
// same fixture.
type identityParityCase struct {
	name     string
	arrange  func(t *testing.T, tpm *identityRecordingTPM)
	grpcCall func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error)
	mcpCall  func(ctx context.Context, p *MCPServiceProvider) (interface{}, error)
	wantCode codes.Code
}

// withoutCreatedAt clears the per-call CreatedAt stamp of an info answer so
// two answers to the same question compare equal.
func withoutCreatedAt(msg proto.Message) proto.Message {
	clone := proto.Clone(msg)
	switch reply := clone.(type) {
	case *platformv1.GetIDevIDInfoResponse:
		reply.GetKeyInfo().CreatedAt = nil
	case *platformv1.GetIAKInfoResponse:
		reply.GetKeyInfo().CreatedAt = nil
	}
	return clone
}

func runIdentityParity(t *testing.T, cases []identityParityCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			svc, provider, tpm := newIdentityParityFixture(t)
			if tc.arrange != nil {
				tc.arrange(t, tpm)
			}

			grpcReply, grpcErr := tc.grpcCall(ctx, svc)
			mcpReply, mcpErr := tc.mcpCall(ctx, provider)

			require.Equal(t, tc.wantCode, status.Code(grpcErr), "gRPC: %v", grpcErr)
			require.Equal(t, status.Code(grpcErr), status.Code(mcpErr), "MCP: %v", mcpErr)
			if grpcErr != nil || grpcReply == nil {
				return
			}
			mcpMessage, ok := mcpReply.(proto.Message)
			require.True(t, ok, "MCP answer %T is not the gRPC message", mcpReply)
			assert.True(t, proto.Equal(withoutCreatedAt(grpcReply), withoutCreatedAt(mcpMessage)),
				"gRPC %v\nMCP  %v", grpcReply, mcpMessage)
		})
	}
}

func idevidAbsent(t *testing.T, tpm *identityRecordingTPM) {
	t.Helper()
	tpm.idevidAttributesErr = errors.New("IDevID key not found")
}

func iakAbsent(t *testing.T, tpm *identityRecordingTPM) {
	t.Helper()
	tpm.iakAttributesErr = errors.New("IAK key not found")
}

func certificatesPresent(t *testing.T, tpm *identityRecordingTPM) {
	t.Helper()
	tpm.readIDevIDCertResult = createIDevIDTestCertificate(t)
	tpm.readIAKCertResult = createIDevIDTestCertificate(t)
}

func certificatesAbsent(t *testing.T, tpm *identityRecordingTPM) {
	t.Helper()
	tpm.readIDevIDCertErr = errors.New("certificate not found")
	tpm.readIAKCertErr = errors.New("certificate not found")
}

func TestMCPIDevIDParity_InfoExistsGetCert(t *testing.T) {
	idevidInfo := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.GetIDevIDInfo(ctx, &platformv1.GetIDevIDInfoRequest{})
	}
	iakInfo := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.GetIAKInfo(ctx, &platformv1.GetIAKInfoRequest{})
	}
	idevidExists := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.HasIDevID(ctx, &platformv1.HasIDevIDRequest{})
	}
	iakExists := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.HasIAK(ctx, &platformv1.HasIAKRequest{})
	}
	mcpIDevIDExists := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		exists, err := p.IDevIDExists(ctx)
		return &platformv1.HasIDevIDResponse{Exists: exists}, err
	}
	mcpIAKExists := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		exists, err := p.IAKExists(ctx)
		return &platformv1.HasIAKResponse{Exists: exists}, err
	}
	idevidCert := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.GetIDevIDCertificate(ctx, &platformv1.GetIDevIDCertificateRequest{})
	}
	iakCert := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.GetIAKCertificate(ctx, &platformv1.GetIAKCertificateRequest{})
	}
	mcpIDevIDCert := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		return p.IDevIDGetCert(ctx, true)
	}
	mcpIAKCert := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		return p.IAKGetCert(ctx, true)
	}

	runIdentityParity(t, []identityParityCase{
		{name: "idevid_info present", arrange: certificatesPresent, grpcCall: idevidInfo,
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) { return p.IDevIDInfo(ctx) }, wantCode: codes.OK},
		{name: "idevid_info absent", arrange: idevidAbsent, grpcCall: idevidInfo,
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) { return p.IDevIDInfo(ctx) }, wantCode: codes.NotFound},
		{name: "iak_info present", arrange: certificatesPresent, grpcCall: iakInfo,
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) { return p.IAKInfo(ctx) }, wantCode: codes.OK},
		{name: "iak_info absent", arrange: iakAbsent, grpcCall: iakInfo,
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) { return p.IAKInfo(ctx) }, wantCode: codes.NotFound},
		{name: "idevid_exists present", grpcCall: idevidExists, mcpCall: mcpIDevIDExists, wantCode: codes.OK},
		{name: "idevid_exists absent", arrange: idevidAbsent, grpcCall: idevidExists, mcpCall: mcpIDevIDExists, wantCode: codes.OK},
		{name: "iak_exists present", grpcCall: iakExists, mcpCall: mcpIAKExists, wantCode: codes.OK},
		{name: "iak_exists absent", arrange: iakAbsent, grpcCall: iakExists, mcpCall: mcpIAKExists, wantCode: codes.OK},
		{name: "idevid_get_cert present", arrange: certificatesPresent, grpcCall: idevidCert, mcpCall: mcpIDevIDCert, wantCode: codes.OK},
		{name: "idevid_get_cert absent", arrange: certificatesAbsent, grpcCall: idevidCert, mcpCall: mcpIDevIDCert, wantCode: codes.NotFound},
		{name: "iak_get_cert present", arrange: certificatesPresent, grpcCall: iakCert, mcpCall: mcpIAKCert, wantCode: codes.OK},
		{name: "iak_get_cert absent", arrange: certificatesAbsent, grpcCall: iakCert, mcpCall: mcpIAKCert, wantCode: codes.NotFound},
	})
}

func TestMCPIDevIDParity_CSRGenerateInstall(t *testing.T) {
	idevidGenerate := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.GenerateIDevID(ctx, &platformv1.GenerateIDevIDRequest{})
	}
	iakGenerate := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.GenerateIAK(ctx, &platformv1.GenerateIAKRequest{})
	}
	mcpIDevIDGenerate := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		return p.IDevIDGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{})
	}
	mcpIAKGenerate := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		return p.IAKGenerate(ctx, &mcp.IDevIDGenerateMCPRequest{})
	}
	idevidCSR := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.CreateIDevIDCSR(ctx, &platformv1.CreateIDevIDCSRRequest{})
	}
	iakCSR := func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
		return svc.CreateIAKCSR(ctx, &platformv1.CreateIAKCSRRequest{})
	}
	mcpIDevIDCSR := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		return p.IDevIDCSR(ctx, &mcp.IDevIDCSRMCPRequest{})
	}
	mcpIAKCSR := func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
		return p.IAKCSR(ctx, &mcp.IDevIDCSRMCPRequest{})
	}
	idevidInstall := func(pemText string) func(context.Context, *IDevIDGRPCService) (proto.Message, error) {
		return func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
			return svc.InstallIDevIDCertificate(ctx, &platformv1.InstallIDevIDCertificateRequest{CertificatePem: []byte(pemText)})
		}
	}
	iakInstall := func(pemText string) func(context.Context, *IDevIDGRPCService) (proto.Message, error) {
		return func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
			return svc.InstallIAKCertificate(ctx, &platformv1.InstallIAKCertificateRequest{CertificatePem: []byte(pemText)})
		}
	}
	mcpIDevIDInstall := func(pemText string) func(context.Context, *MCPServiceProvider) (interface{}, error) {
		return func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
			return p.IDevIDInstallCert(ctx, pemText)
		}
	}
	mcpIAKInstall := func(pemText string) func(context.Context, *MCPServiceProvider) (interface{}, error) {
		return func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
			return p.IAKInstallCert(ctx, pemText)
		}
	}
	certPEM := string(createIDevIDTestCertificatePEM(t))
	keyMismatch := func(t *testing.T, tpm *identityRecordingTPM) {
		t.Helper()
		tpm.writeIDevIDCertErr = errors.New("invalid certificate: public key does not match")
		tpm.writeIAKCertErr = errors.New("invalid certificate: public key does not match")
	}

	runIdentityParity(t, []identityParityCase{
		{name: "idevid_generate", grpcCall: idevidGenerate, mcpCall: mcpIDevIDGenerate, wantCode: codes.OK},
		{name: "idevid_generate EK missing", grpcCall: idevidGenerate, mcpCall: mcpIDevIDGenerate, wantCode: codes.NotFound,
			arrange: func(t *testing.T, tpm *identityRecordingTPM) { tpm.ekAttributesErr = errors.New("EK not found") }},
		{name: "iak_generate", grpcCall: iakGenerate, mcpCall: mcpIAKGenerate, wantCode: codes.OK},
		{name: "iak_generate EK missing", grpcCall: iakGenerate, mcpCall: mcpIAKGenerate, wantCode: codes.NotFound,
			arrange: func(t *testing.T, tpm *identityRecordingTPM) { tpm.ekAttributesErr = errors.New("EK not found") }},
		{name: "idevid_csr", grpcCall: idevidCSR, mcpCall: mcpIDevIDCSR, wantCode: codes.OK},
		{name: "idevid_csr IDevID absent", arrange: idevidAbsent, grpcCall: idevidCSR, mcpCall: mcpIDevIDCSR, wantCode: codes.NotFound},
		{name: "iak_csr", grpcCall: iakCSR, mcpCall: mcpIAKCSR, wantCode: codes.OK},
		{name: "iak_csr IAK absent", arrange: iakAbsent, grpcCall: iakCSR, mcpCall: mcpIAKCSR, wantCode: codes.NotFound},
		{name: "idevid_install_cert", grpcCall: idevidInstall(certPEM), mcpCall: mcpIDevIDInstall(certPEM), wantCode: codes.OK},
		{name: "idevid_install_cert empty PEM", grpcCall: idevidInstall(""), mcpCall: mcpIDevIDInstall(""), wantCode: codes.InvalidArgument},
		{name: "idevid_install_cert not PEM", grpcCall: idevidInstall("not a pem"), mcpCall: mcpIDevIDInstall("not a pem"), wantCode: codes.InvalidArgument},
		{name: "idevid_install_cert key mismatch", arrange: keyMismatch, grpcCall: idevidInstall(certPEM), mcpCall: mcpIDevIDInstall(certPEM), wantCode: codes.InvalidArgument},
		{name: "iak_install_cert", grpcCall: iakInstall(certPEM), mcpCall: mcpIAKInstall(certPEM), wantCode: codes.OK},
		{name: "iak_install_cert empty PEM", grpcCall: iakInstall(""), mcpCall: mcpIAKInstall(""), wantCode: codes.InvalidArgument},
		{name: "iak_install_cert not PEM", grpcCall: iakInstall("not a pem"), mcpCall: mcpIAKInstall("not a pem"), wantCode: codes.InvalidArgument},
		{name: "iak_install_cert key mismatch", arrange: keyMismatch, grpcCall: iakInstall(certPEM), mcpCall: mcpIAKInstall(certPEM), wantCode: codes.InvalidArgument},
	})
}

func TestMCPIDevIDParity_Delete(t *testing.T) {
	deleteOnly := func(err error) (proto.Message, error) { return nil, err }
	certNotFound := func(t *testing.T, tpm *identityRecordingTPM) {
		t.Helper()
		tpm.deleteIDevIDCertErr = errors.New("certificate not found")
		tpm.deleteIAKCertErr = errors.New("certificate not found")
	}

	runIdentityParity(t, []identityParityCase{
		{name: "idevid_delete refuses", wantCode: codes.FailedPrecondition,
			grpcCall: func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
				return svc.DeleteIDevID(ctx, &platformv1.DeleteIDevIDRequest{})
			},
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return deleteOnly(p.IDevIDDelete(ctx))
			}},
		{name: "iak_delete refuses", wantCode: codes.FailedPrecondition,
			grpcCall: func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
				return svc.DeleteIAK(ctx, &platformv1.DeleteIAKRequest{})
			},
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return deleteOnly(p.IAKDelete(ctx))
			}},
		{name: "idevid_delete_cert", wantCode: codes.OK,
			grpcCall: func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
				_, err := svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})
				return deleteOnly(err)
			},
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return deleteOnly(p.IDevIDDeleteCert(ctx))
			}},
		{name: "idevid_delete_cert absent", arrange: certNotFound, wantCode: codes.NotFound,
			grpcCall: func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
				_, err := svc.DeleteIDevIDCertificate(ctx, &platformv1.DeleteIDevIDCertificateRequest{})
				return deleteOnly(err)
			},
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return deleteOnly(p.IDevIDDeleteCert(ctx))
			}},
		{name: "iak_delete_cert", wantCode: codes.OK,
			grpcCall: func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
				_, err := svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})
				return deleteOnly(err)
			},
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return deleteOnly(p.IAKDeleteCert(ctx))
			}},
		{name: "iak_delete_cert absent", arrange: certNotFound, wantCode: codes.NotFound,
			grpcCall: func(ctx context.Context, svc *IDevIDGRPCService) (proto.Message, error) {
				_, err := svc.DeleteIAKCertificate(ctx, &platformv1.DeleteIAKCertificateRequest{})
				return deleteOnly(err)
			},
			mcpCall: func(ctx context.Context, p *MCPServiceProvider) (interface{}, error) {
				return deleteOnly(p.IAKDeleteCert(ctx))
			}},
	})
}

// TestMCPIDevIDInfo_AbsentKeyIsNotFound fails on f8a86963, where the MCP info
// tools answered {"exists": false} with no error and so hid every TPM fault.
func TestMCPIDevIDInfo_AbsentKeyIsNotFound(t *testing.T) {
	ctx := context.Background()
	_, provider, tpm := newIdentityParityFixture(t)
	idevidAbsent(t, tpm)
	iakAbsent(t, tpm)

	idevidReply, err := provider.IDevIDInfo(ctx)
	assert.Nil(t, idevidReply)
	assert.Equal(t, codes.NotFound, status.Code(err))

	iakReply, err := provider.IAKInfo(ctx)
	assert.Nil(t, iakReply)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestMCPIDevIDDelete_RefusesAndKeepsCertificate fails on f8a86963, where the
// MCP key-delete tools reported success without evicting the key.
func TestMCPIDevIDDelete_RefusesAndKeepsCertificate(t *testing.T) {
	ctx := context.Background()
	_, provider, tpm := newIdentityParityFixture(t)

	var refusal ErrDeviceIdentityKeyNotDeletable

	err := provider.IDevIDDelete(ctx)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "IDevID", refusal.Key)

	err = provider.IAKDelete(ctx)
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "IAK", refusal.Key)

	assert.Zero(t, tpm.idevidCertDeletes, "the refusal must not touch the IDevID certificate")
	assert.Zero(t, tpm.iakCertDeletes, "the refusal must not touch the IAK certificate")
}

func TestMCPIDevID_ServiceNotConfigured(t *testing.T) {
	ctx := context.Background()
	provider := NewMCPServiceProvider(&MCPServiceProviderConfig{Logger: slog.Default()})

	calls := map[string]func() error{
		"idevid_info":         func() error { _, err := provider.IDevIDInfo(ctx); return err },
		"idevid_exists":       func() error { _, err := provider.IDevIDExists(ctx); return err },
		"idevid_get_cert":     func() error { _, err := provider.IDevIDGetCert(ctx, false); return err },
		"idevid_generate":     func() error { _, err := provider.IDevIDGenerate(ctx, nil); return err },
		"idevid_csr":          func() error { _, err := provider.IDevIDCSR(ctx, nil); return err },
		"idevid_install_cert": func() error { _, err := provider.IDevIDInstallCert(ctx, ""); return err },
		"idevid_delete":       func() error { return provider.IDevIDDelete(ctx) },
		"idevid_delete_cert":  func() error { return provider.IDevIDDeleteCert(ctx) },
		"iak_info":            func() error { _, err := provider.IAKInfo(ctx); return err },
		"iak_exists":          func() error { _, err := provider.IAKExists(ctx); return err },
		"iak_get_cert":        func() error { _, err := provider.IAKGetCert(ctx, false); return err },
		"iak_generate":        func() error { _, err := provider.IAKGenerate(ctx, nil); return err },
		"iak_csr":             func() error { _, err := provider.IAKCSR(ctx, nil); return err },
		"iak_install_cert":    func() error { _, err := provider.IAKInstallCert(ctx, ""); return err },
		"iak_delete":          func() error { return provider.IAKDelete(ctx) },
		"iak_delete_cert":     func() error { return provider.IAKDeleteCert(ctx) },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.ErrorIs(t, err, ErrIDevIDServiceNotConfigured{})
			assert.Equal(t, codes.Unavailable, status.Code(err))
		})
	}
}

func TestMCPIDevIDGetCert_IncludePEM(t *testing.T) {
	ctx := context.Background()
	_, provider, tpm := newIdentityParityFixture(t)
	certificatesPresent(t, tpm)

	withPEM, err := provider.IDevIDGetCert(ctx, true)
	require.NoError(t, err)
	assert.NotEmpty(t, withPEM.(*platformv1.GetIDevIDCertificateResponse).GetCertificate().GetPem())

	withoutPEM, err := provider.IAKGetCert(ctx, false)
	require.NoError(t, err)
	reply := withoutPEM.(*platformv1.GetIAKCertificateResponse)
	assert.Empty(t, reply.GetCertificate().GetPem())
	assert.NotEmpty(t, reply.GetCertificate().GetSubjectCn())
}
