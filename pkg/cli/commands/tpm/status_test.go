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

package tpm

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
	tpmsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/tpm"
)

// =============================================================================
// Mock IDevID Service Client (the surface `tpm status` shares with
// `tpm iak info` / `tpm idevid info`)
// =============================================================================

type mockIDevIDServiceClient struct {
	platformv1.IDevIDServiceClient

	hasIAKFunc        func(ctx context.Context, req *platformv1.HasIAKRequest, opts ...grpc.CallOption) (*platformv1.HasIAKResponse, error)
	getIAKInfoFunc    func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error)
	getIAKCertFunc    func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error)
	hasIDevIDFunc     func(ctx context.Context, req *platformv1.HasIDevIDRequest, opts ...grpc.CallOption) (*platformv1.HasIDevIDResponse, error)
	getIDevIDInfoFunc func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error)
	getIDevIDCertFunc func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error)
}

func (m *mockIDevIDServiceClient) HasIAK(ctx context.Context, req *platformv1.HasIAKRequest, opts ...grpc.CallOption) (*platformv1.HasIAKResponse, error) {
	if m.hasIAKFunc != nil {
		return m.hasIAKFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: HasIAK not configured")
}

func (m *mockIDevIDServiceClient) GetIAKInfo(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
	if m.getIAKInfoFunc != nil {
		return m.getIAKInfoFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIAKInfo not configured")
}

func (m *mockIDevIDServiceClient) GetIAKCertificate(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
	if m.getIAKCertFunc != nil {
		return m.getIAKCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIAKCertificate not configured")
}

func (m *mockIDevIDServiceClient) HasIDevID(ctx context.Context, req *platformv1.HasIDevIDRequest, opts ...grpc.CallOption) (*platformv1.HasIDevIDResponse, error) {
	if m.hasIDevIDFunc != nil {
		return m.hasIDevIDFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: HasIDevID not configured")
}

func (m *mockIDevIDServiceClient) GetIDevIDInfo(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
	if m.getIDevIDInfoFunc != nil {
		return m.getIDevIDInfoFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIDevIDInfo not configured")
}

func (m *mockIDevIDServiceClient) GetIDevIDCertificate(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
	if m.getIDevIDCertFunc != nil {
		return m.getIDevIDCertFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock: GetIDevIDCertificate not configured")
}

// =============================================================================
// Fixtures
// =============================================================================

const (
	statusTestIssuerCN     = "ca01.cp.example.com"
	statusTestIAKHandle    = 0x81010002
	statusTestIDevIDHandle = 0x81020000
	statusTestSSRKHandle   = 0x81000001
)

// tcgPolicyOIDs are the TCG DevID certificate policy arcs: .1 and .2 are
// what the fleet's current IAK certificates carry; .3 is
// tcg-cap-verifiedTPMRestricted, the one the verifier requires.
var (
	oidTCGPolicy1 = quicbaasca.TCGVerifiedTPMResidencyPolicy
	oidTCGPolicy2 = quicbaasca.TCGVerifiedTPMFixedPolicy
	oidTCGPolicy3 = quicbaasca.TCGVerifiedTPMRestrictedPolicy
)

// testCertificatePEM issues a self-signed certificate carrying the given
// certificatePolicies and returns it PEM-encoded.
func testCertificatePEM(t *testing.T, subjectCN string, policies ...x509.OID) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4711),
		Subject:      pkix.Name{CommonName: subjectCN},
		Issuer:       pkix.Name{CommonName: statusTestIssuerCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		Policies:     policies,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pemEncodeCertificate(der))
}

func pemEncodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// deviceKeyInfoProto is the payload GetIAKInfo/GetIDevIDInfo return for a
// provisioned key with an installed certificate.
func deviceKeyInfoProto(handle uint32, withCert bool) *platformv1.DeviceKeyInfo {
	info := &platformv1.DeviceKeyInfo{
		Handle:         handle,
		Algorithm:      platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P256,
		HasCertificate: withCert,
	}
	if withCert {
		info.CertificateInfo = &platformv1.DeviceIdentityCertificate{IssuerCn: statusTestIssuerCN}
	}
	return info
}

// statusFixture is a fully provisioned node as the fleet reports it:
// every object present, both certificates installed.
type statusFixture struct {
	tpm    *mockTPMServiceClient
	idevid *mockIDevIDServiceClient
}

func newAllPresentFixture(t *testing.T, iakPolicies ...x509.OID) *statusFixture {
	t.Helper()
	iakPEM := testCertificatePEM(t, "SuperMicro X10-1234", iakPolicies...)
	idevidPEM := testCertificatePEM(t, "node-02-idevid", oidTCGPolicy1)
	return &statusFixture{
		tpm: &mockTPMServiceClient{
			infoFunc: func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
				return &platformv1.TPMInfoResponse{Properties: map[string]string{"manufacturer": "IFX", "firmware": "5.63"}}, nil
			},
			getEKCertFunc: func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
				return &platformv1.GetEKCertificateResponse{Certificate: []byte("cert"), Format: "PEM"}, nil
			},
			getSRKFunc: func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
				handle := req.GetHandle()
				if handle == 0 {
					handle = statusTestSSRKHandle
				}
				return &platformv1.GetSRKResponse{Handle: handle}, nil
			},
			getPCRsFunc: func(ctx context.Context, req *platformv1.GetPCRsRequest, opts ...grpc.CallOption) (*platformv1.GetPCRsResponse, error) {
				return &platformv1.GetPCRsResponse{PcrValues: []*platformv1.PCRValue{{Index: 23, Value: []byte{0xab, 0x01}}}}, nil
			},
		},
		idevid: &mockIDevIDServiceClient{
			hasIAKFunc: func(ctx context.Context, req *platformv1.HasIAKRequest, opts ...grpc.CallOption) (*platformv1.HasIAKResponse, error) {
				return &platformv1.HasIAKResponse{Exists: true}, nil
			},
			getIAKInfoFunc: func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
				return &platformv1.GetIAKInfoResponse{KeyInfo: deviceKeyInfoProto(statusTestIAKHandle, true)}, nil
			},
			getIAKCertFunc: func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
				return &platformv1.GetIAKCertificateResponse{Certificate: &platformv1.DeviceIdentityCertificate{Pem: []byte(iakPEM), IssuerCn: statusTestIssuerCN}}, nil
			},
			hasIDevIDFunc: func(ctx context.Context, req *platformv1.HasIDevIDRequest, opts ...grpc.CallOption) (*platformv1.HasIDevIDResponse, error) {
				return &platformv1.HasIDevIDResponse{Exists: true}, nil
			},
			getIDevIDInfoFunc: func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
				return &platformv1.GetIDevIDInfoResponse{KeyInfo: deviceKeyInfoProto(statusTestIDevIDHandle, true)}, nil
			},
			getIDevIDCertFunc: func(ctx context.Context, req *platformv1.GetIDevIDCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDCertificateResponse, error) {
				return &platformv1.GetIDevIDCertificateResponse{Certificate: &platformv1.DeviceIdentityCertificate{Pem: []byte(idevidPEM), IssuerCn: statusTestIssuerCN}}, nil
			},
		},
	}
}

func (f *statusFixture) clients() statusClients {
	return statusClients{
		tpm:    tpmsvc.NewClientFromGRPC(f.tpm),
		idevid: idevidsvc.NewClientFromGRPC(f.idevid),
	}
}

func defaultStatusOptions() statusOptions {
	return statusOptions{PlatformSRKHandle: defaultPlatformSRKHandle}
}

func objectByName(t *testing.T, report *tpmStatusReport, name string) tpmObjectStatus {
	t.Helper()
	for _, obj := range report.Objects {
		if obj.Name == name {
			return obj
		}
	}
	t.Fatalf("report has no %q row", name)
	return tpmObjectStatus{}
}

// renderTable prints the report as the table view and returns the text.
func renderTable(t *testing.T, report *tpmStatusReport) string {
	t.Helper()
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &out)
	require.NoError(t, printStatusTable(printer, report))
	return out.String()
}

// tableRow returns the rendered line for one object.
func tableRow(t *testing.T, table, name string) string {
	t.Helper()
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, name+" ") {
			return line
		}
	}
	t.Fatalf("table has no %q row:\n%s", name, table)
	return ""
}

var statusObjectNames = []string{"EK", "SSRK", "PlatformSRK", "IAK", "IDevID"}

// =============================================================================
// Report tests
// =============================================================================

// TestBuildStatusReport_AllPresent is the regression for #471: a node that
// `tpm iak info` / `tpm idevid info` / `tpm srk info --handle 0x81000002`
// show as fully provisioned must render five present rows.
func TestBuildStatusReport_AllPresent(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy1, oidTCGPolicy2, oidTCGPolicy3)
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	require.Len(t, report.Objects, 5)
	for _, name := range statusObjectNames {
		obj := objectByName(t, report, name)
		assert.True(t, obj.HandlePresent, "%s handle_present", name)
		assert.Empty(t, obj.Error, "%s error", name)
	}

	iak := objectByName(t, report, "IAK")
	assert.True(t, iak.CertPresent)
	assert.Equal(t, "0x81010002", iak.Handle)
	assert.Equal(t, statusTestIssuerCN, iak.Issuer)
	assert.Equal(t, []string{"2.23.133.11.1.1", "2.23.133.11.1.2", "2.23.133.11.1.3"}, iak.CertPolicies)
	require.NotNil(t, iak.VerifiedTPMRestricted)
	assert.True(t, *iak.VerifiedTPMRestricted)

	idevid := objectByName(t, report, "IDevID")
	assert.True(t, idevid.CertPresent)
	assert.Equal(t, "0x81020000", idevid.Handle)
	assert.Equal(t, statusTestIssuerCN, idevid.Issuer)
	assert.Nil(t, idevid.VerifiedTPMRestricted, "the Restricted verdict applies to the IAK only")

	assert.Equal(t, "0x81000002", objectByName(t, report, "PlatformSRK").Handle)
	assert.Equal(t, "0x81000001", objectByName(t, report, "SSRK").Handle)
	assert.Equal(t, "IFX", report.Manufacturer)
	assert.Equal(t, "5.63", report.FirmwareVersion)
	assert.True(t, report.PCR23Extended)
	assert.Equal(t, "ab01", report.PCR23Hex)

	table := renderTable(t, report)
	assert.NotContains(t, table, "absent")
	assert.NotContains(t, table, "error")
	for _, name := range statusObjectNames {
		assert.Contains(t, tableRow(t, table, name), "present", "%s row", name)
	}
	iakRow := tableRow(t, table, "IAK")
	assert.Contains(t, iakRow, "verifiedTPMRestricted")
	assert.NotContains(t, iakRow, verifiedTPMRestrictedNote)
	assert.Contains(t, iakRow, "issuer "+statusTestIssuerCN)
	assert.Contains(t, tableRow(t, table, "PlatformSRK"), "0x81000002; default handle assumed")
}

// TestBuildStatusReport_IAKCertLacksRestricted covers the fleet's current
// state: the IAK certificate carries the TCG .1 and .2 policies but not
// verifiedTPMRestricted, so the verifier will reject it and status must
// say so on the certificate column.
func TestBuildStatusReport_IAKCertLacksRestricted(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy1, oidTCGPolicy2)
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	iak := objectByName(t, report, "IAK")
	assert.True(t, iak.HandlePresent)
	assert.True(t, iak.CertPresent)
	assert.Equal(t, []string{"2.23.133.11.1.1", "2.23.133.11.1.2"}, iak.CertPolicies)
	require.NotNil(t, iak.VerifiedTPMRestricted)
	assert.False(t, *iak.VerifiedTPMRestricted)

	table := renderTable(t, report)
	iakRow := tableRow(t, table, "IAK")
	assert.Contains(t, iakRow, "present ("+verifiedTPMRestrictedNote+")")
	assert.NotContains(t, iakRow, "absent")
	assert.NotContains(t, tableRow(t, table, "IDevID"), verifiedTPMRestrictedNote)
}

// TestBuildStatusReport_IAKMissing: only the row the daemon positively
// reports missing flips to absent.
func TestBuildStatusReport_IAKMissing(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.idevid.hasIAKFunc = func(ctx context.Context, req *platformv1.HasIAKRequest, opts ...grpc.CallOption) (*platformv1.HasIAKResponse, error) {
		return &platformv1.HasIAKResponse{Exists: false}, nil
	}
	fx.idevid.getIAKInfoFunc = func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
		t.Fatal("GetIAKInfo must not be called once HasIAK reported the key missing")
		return nil, nil
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	iak := objectByName(t, report, "IAK")
	assert.False(t, iak.HandlePresent)
	assert.False(t, iak.CertPresent)
	assert.Empty(t, iak.Error)
	assert.Contains(t, iak.Note, "tpm iak generate")
	for _, name := range []string{"EK", "SSRK", "PlatformSRK", "IDevID"} {
		assert.True(t, objectByName(t, report, name).HandlePresent, "%s must stay present", name)
	}

	table := renderTable(t, report)
	assert.Contains(t, tableRow(t, table, "IAK"), "absent")
	assert.Equal(t, 1, strings.Count(table, "absent"))
}

// TestBuildStatusReport_IAKInfoNotFoundAfterHas: a NotFound from the info
// RPC (the key vanished between the two calls) is still a positive
// absence, not an error.
func TestBuildStatusReport_IAKInfoNotFoundAfterHas(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.idevid.getIAKInfoFunc = func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
		return nil, status.Error(codes.NotFound, "IAK not found")
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())
	iak := objectByName(t, report, "IAK")
	assert.False(t, iak.HandlePresent)
	assert.Empty(t, iak.Error)
}

// TestBuildStatusReport_PlatformSRKNotFound: the daemon's NotFound for the
// platform handle is the one signal that makes that row absent.
func TestBuildStatusReport_PlatformSRKNotFound(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.tpm.getSRKFunc = func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
		if req.GetHandle() == defaultPlatformSRKHandle {
			return nil, status.Error(codes.NotFound, "PlatformSRK not found")
		}
		return &platformv1.GetSRKResponse{Handle: statusTestSSRKHandle}, nil
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	psrk := objectByName(t, report, "PlatformSRK")
	assert.False(t, psrk.HandlePresent)
	assert.Empty(t, psrk.Error)
	assert.Equal(t, "0x81000002", psrk.Handle, "the probed handle is recorded even when absent")
	assert.True(t, objectByName(t, report, "SSRK").HandlePresent)

	table := renderTable(t, report)
	assert.Equal(t, 1, strings.Count(table, "absent"))
	assert.Contains(t, tableRow(t, table, "PlatformSRK"), "absent")
}

// TestBuildStatusReport_SDKErrors: when every lookup fails for a reason
// other than not-found, every row says error and none says absent.
func TestBuildStatusReport_SDKErrors(t *testing.T) {
	boom := status.Error(codes.Unavailable, "TPM service not available")
	fx := &statusFixture{
		tpm: &mockTPMServiceClient{
			getEKCertFunc: func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
				return nil, boom
			},
			getSRKFunc: func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
				return nil, boom
			},
		},
		idevid: &mockIDevIDServiceClient{
			hasIAKFunc: func(ctx context.Context, req *platformv1.HasIAKRequest, opts ...grpc.CallOption) (*platformv1.HasIAKResponse, error) {
				return nil, boom
			},
			hasIDevIDFunc: func(ctx context.Context, req *platformv1.HasIDevIDRequest, opts ...grpc.CallOption) (*platformv1.HasIDevIDResponse, error) {
				return nil, boom
			},
		},
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	require.Len(t, report.Objects, 5)
	for _, name := range statusObjectNames {
		obj := objectByName(t, report, name)
		assert.False(t, obj.HandlePresent, "%s", name)
		assert.Contains(t, obj.Error, "TPM service not available", "%s", name)
	}
	assert.False(t, report.PCR23Extended)
	assert.Empty(t, report.PCR23Hex)

	table := renderTable(t, report)
	assert.NotContains(t, table, "absent")
	for _, name := range statusObjectNames {
		row := tableRow(t, table, name)
		assert.Contains(t, row, "error: ")
		assert.Contains(t, row, "TPM service not available")
	}
}

// TestBuildStatusReport_DeviceKeyInfoError: Has* succeeded but the info
// RPC failed for a non-not-found reason; the row is an error, not absent.
func TestBuildStatusReport_DeviceKeyInfoError(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.idevid.getIDevIDInfoFunc = func(ctx context.Context, req *platformv1.GetIDevIDInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIDevIDInfoResponse, error) {
		return nil, status.Error(codes.Internal, "tpm read failed")
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())
	idevid := objectByName(t, report, "IDevID")
	assert.False(t, idevid.HandlePresent)
	assert.Contains(t, idevid.Error, "tpm read failed")
	assert.Contains(t, tableRow(t, renderTable(t, report), "IDevID"), "error")
}

// TestBuildStatusReport_CertificateDetailUnavailable: the key and
// certificate are present but the certificate RPC fails; presence is kept
// and the note explains why there is no policy verdict.
func TestBuildStatusReport_CertificateDetailUnavailable(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.idevid.getIAKCertFunc = func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
		return nil, status.Error(codes.Internal, "cert store unavailable")
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())
	iak := objectByName(t, report, "IAK")
	assert.True(t, iak.HandlePresent)
	assert.True(t, iak.CertPresent)
	assert.Nil(t, iak.VerifiedTPMRestricted)
	assert.Contains(t, iak.Note, "certificate detail unavailable")
	assert.Contains(t, iak.Note, "cert store unavailable")
	assert.Equal(t, statusTestIssuerCN, iak.Issuer, "issuer still comes from the info RPC")
}

// TestBuildStatusReport_CertificateUnparseable: garbage PEM is reported,
// not rendered as a missing Restricted policy.
func TestBuildStatusReport_CertificateUnparseable(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.idevid.getIAKCertFunc = func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
		return &platformv1.GetIAKCertificateResponse{Certificate: &platformv1.DeviceIdentityCertificate{Pem: []byte("not a certificate")}}, nil
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())
	iak := objectByName(t, report, "IAK")
	assert.True(t, iak.CertPresent)
	assert.Nil(t, iak.VerifiedTPMRestricted)
	assert.Contains(t, iak.Note, "certificate unparseable")
	assert.Contains(t, iak.Note, ErrStatusCertificatePEM{}.Error())
	assert.NotContains(t, renderTable(t, report), verifiedTPMRestrictedNote)
}

// TestBuildStatusReport_KeyWithoutCertificate: a generated but unenrolled
// key is present with no certificate.
func TestBuildStatusReport_KeyWithoutCertificate(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.idevid.getIAKInfoFunc = func(ctx context.Context, req *platformv1.GetIAKInfoRequest, opts ...grpc.CallOption) (*platformv1.GetIAKInfoResponse, error) {
		return &platformv1.GetIAKInfoResponse{KeyInfo: deviceKeyInfoProto(statusTestIAKHandle, false)}, nil
	}
	fx.idevid.getIAKCertFunc = func(ctx context.Context, req *platformv1.GetIAKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetIAKCertificateResponse, error) {
		t.Fatal("GetIAKCertificate must not be called when info reports no certificate")
		return nil, nil
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())
	iak := objectByName(t, report, "IAK")
	assert.True(t, iak.HandlePresent)
	assert.False(t, iak.CertPresent)
	assert.Empty(t, iak.Error)
	row := tableRow(t, renderTable(t, report), "IAK")
	assert.Contains(t, row, "present")
	assert.Contains(t, row, "n/a")
}

// TestBuildStatusReport_PlatformSRKHandleFlag: an explicit handle is
// probed and the note credits the flag instead of the default.
func TestBuildStatusReport_PlatformSRKHandleFlag(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	var probed []uint32
	fx.tpm.getSRKFunc = func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
		probed = append(probed, req.GetHandle())
		handle := req.GetHandle()
		if handle == 0 {
			handle = statusTestSSRKHandle
		}
		return &platformv1.GetSRKResponse{Handle: handle}, nil
	}
	opts := statusOptions{PlatformSRKHandle: 0x81000005, PlatformSRKHandleExplicit: true}
	report := buildStatusReport(context.Background(), fx.clients(), opts)

	assert.Equal(t, []uint32{0, 0x81000005}, probed)
	psrk := objectByName(t, report, "PlatformSRK")
	assert.True(t, psrk.HandlePresent)
	assert.Equal(t, "0x81000005", psrk.Handle)
	assert.Contains(t, psrk.Note, "--platform-srk-handle")
	assert.NotContains(t, psrk.Note, "default")
}

// platformHandleProbe wires the fixture so Info reports the given
// properties and GetSRK records every handle it is asked about.
func platformHandleProbe(fx *statusFixture, props map[string]string) *[]uint32 {
	probed := &[]uint32{}
	fx.tpm.infoFunc = func(ctx context.Context, req *platformv1.TPMInfoRequest, opts ...grpc.CallOption) (*platformv1.TPMInfoResponse, error) {
		return &platformv1.TPMInfoResponse{Properties: props}, nil
	}
	fx.tpm.getSRKFunc = func(ctx context.Context, req *platformv1.GetSRKRequest, opts ...grpc.CallOption) (*platformv1.GetSRKResponse, error) {
		*probed = append(*probed, req.GetHandle())
		handle := req.GetHandle()
		if handle == 0 {
			handle = statusTestSSRKHandle
		}
		return &platformv1.GetSRKResponse{Handle: handle}, nil
	}
	return probed
}

// TestBuildStatusReport_PlatformSRKHandleFromDaemon is the regression for
// #477: a node configured with a non-default handle is probed at that
// handle without any flag, and the note names the daemon as the source.
func TestBuildStatusReport_PlatformSRKHandleFromDaemon(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	probed := platformHandleProbe(fx, map[string]string{"platform_srk_handle": "0x81000005"})

	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	assert.Equal(t, []uint32{0, 0x81000005}, *probed)
	psrk := objectByName(t, report, "PlatformSRK")
	assert.True(t, psrk.HandlePresent)
	assert.Equal(t, "0x81000005", psrk.Handle)
	assert.Equal(t, "handle from daemon config", psrk.Note)
}

// TestBuildStatusReport_PlatformSRKFlagBeatsDaemon: the explicit flag stays
// the operator's override even when the daemon reports a handle.
func TestBuildStatusReport_PlatformSRKFlagBeatsDaemon(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	probed := platformHandleProbe(fx, map[string]string{"platform_srk_handle": "0x81000005"})
	opts := statusOptions{PlatformSRKHandle: 0x81000009, PlatformSRKHandleExplicit: true}

	report := buildStatusReport(context.Background(), fx.clients(), opts)

	assert.Equal(t, []uint32{0, 0x81000009}, *probed)
	psrk := objectByName(t, report, "PlatformSRK")
	assert.Equal(t, "0x81000009", psrk.Handle)
	assert.Equal(t, "handle from --platform-srk-handle", psrk.Note)
}

// TestBuildStatusReport_PlatformSRKDefaultWhenDaemonSilent: an older daemon
// reports no handle, so the default is probed with the assumption note.
func TestBuildStatusReport_PlatformSRKDefaultWhenDaemonSilent(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	probed := platformHandleProbe(fx, map[string]string{"manufacturer": "IFX"})

	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	assert.Equal(t, []uint32{0, defaultPlatformSRKHandle}, *probed)
	assert.Contains(t, objectByName(t, report, "PlatformSRK").Note, "default handle assumed")
}

func TestResolvePlatformSRKHandle(t *testing.T) {
	def := statusOptions{PlatformSRKHandle: defaultPlatformSRKHandle}
	explicit := statusOptions{PlatformSRKHandle: 0x81000009, PlatformSRKHandleExplicit: true}

	cases := map[string]struct {
		opts       statusOptions
		props      map[string]string
		wantHandle uint32
		wantNote   string
	}{
		"daemon handle": {
			opts: def, props: map[string]string{"platform_srk_handle": "0x8100000A"},
			wantHandle: 0x8100000A, wantNote: "handle from daemon config",
		},
		"flag wins": {
			opts: explicit, props: map[string]string{"platform_srk_handle": "0x8100000A"},
			wantHandle: 0x81000009, wantNote: "handle from --platform-srk-handle",
		},
		"no properties at all": {
			opts: def, props: nil,
			wantHandle: defaultPlatformSRKHandle, wantNote: platformSRKHandleNote(def),
		},
		"unparseable property": {
			opts: def, props: map[string]string{"platform_srk_handle": "not-a-handle"},
			wantHandle: defaultPlatformSRKHandle, wantNote: platformSRKHandleNote(def),
		},
		"zero property": {
			opts: def, props: map[string]string{"platform_srk_handle": "0x00000000"},
			wantHandle: defaultPlatformSRKHandle, wantNote: platformSRKHandleNote(def),
		},
		"out of range property": {
			opts: def, props: map[string]string{"platform_srk_handle": "0x1FFFFFFFF"},
			wantHandle: defaultPlatformSRKHandle, wantNote: platformSRKHandleNote(def),
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			handle, note := resolvePlatformSRKHandle(tc.opts, tc.props)

			assert.Equal(t, tc.wantHandle, handle)
			assert.Equal(t, tc.wantNote, note)
		})
	}
}

// TestBuildStatusReport_EKNotFound: the EK row honours the same positive
// not-found rule as the others.
func TestBuildStatusReport_EKNotFound(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy3)
	fx.tpm.getEKCertFunc = func(ctx context.Context, req *platformv1.GetEKCertificateRequest, opts ...grpc.CallOption) (*platformv1.GetEKCertificateResponse, error) {
		return nil, status.Error(codes.NotFound, "EK certificate not found")
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())
	ek := objectByName(t, report, "EK")
	assert.False(t, ek.HandlePresent)
	assert.Empty(t, ek.Error)
}

// TestStatusReport_JSONShape: the pre-#471 keys are unchanged and the
// new keys are additive and omitted when empty.
func TestStatusReport_JSONShape(t *testing.T) {
	fx := newAllPresentFixture(t, oidTCGPolicy1, oidTCGPolicy2)
	fx.idevid.hasIDevIDFunc = func(ctx context.Context, req *platformv1.HasIDevIDRequest, opts ...grpc.CallOption) (*platformv1.HasIDevIDResponse, error) {
		return &platformv1.HasIDevIDResponse{Exists: false}, nil
	}
	report := buildStatusReport(context.Background(), fx.clients(), defaultStatusOptions())

	raw, err := json.Marshal(report)
	require.NoError(t, err)
	var doc struct {
		PCR23Extended bool                     `json:"pcr23_extended"`
		Objects       []map[string]interface{} `json:"objects"`
	}
	require.NoError(t, json.Unmarshal(raw, &doc))
	require.Len(t, doc.Objects, 5)

	byName := map[string]map[string]interface{}{}
	for _, obj := range doc.Objects {
		byName[obj["name"].(string)] = obj
	}
	for _, name := range statusObjectNames {
		obj := byName[name]
		for _, key := range []string{"name", "role", "handle_present", "cert_present"} {
			assert.Contains(t, obj, key, "%s.%s", name, key)
		}
		assert.NotContains(t, obj, "error", "%s", name)
	}
	iak := byName["IAK"]
	assert.Equal(t, true, iak["handle_present"])
	assert.Equal(t, "0x81010002", iak["handle"])
	assert.Equal(t, false, iak["verified_tpm_restricted"])
	assert.Equal(t, []interface{}{"2.23.133.11.1.1", "2.23.133.11.1.2"}, iak["cert_policies"])

	idevid := byName["IDevID"]
	assert.Equal(t, false, idevid["handle_present"])
	assert.NotContains(t, idevid, "handle")
	assert.NotContains(t, idevid, "verified_tpm_restricted")
	assert.NotContains(t, idevid, "cert_policies")
	assert.Contains(t, idevid["note"], "tpm idevid generate")
}

// =============================================================================
// Helper tests
// =============================================================================

func TestIsNotFound(t *testing.T) {
	assert.False(t, isNotFound(nil))
	assert.True(t, isNotFound(status.Error(codes.NotFound, "gone")))
	assert.True(t, isNotFound(&tpmsvc.ErrGetSRKFailed{Cause: status.Error(codes.NotFound, "gone")}),
		"the SDK wrapper unwraps to the gRPC status")
	assert.True(t, isNotFound(&idevidsvc.ErrIAKNotFound{}))
	assert.True(t, isNotFound(&idevidsvc.ErrIDevIDNotFound{}))
	assert.False(t, isNotFound(status.Error(codes.Unavailable, "down")))
	assert.False(t, isNotFound(errors.New("plain error")))
}

func TestParseCertificatePEM(t *testing.T) {
	pemStr := testCertificatePEM(t, "x", oidTCGPolicy3)
	cert, err := parseCertificatePEM(pemStr)
	require.NoError(t, err)
	assert.Equal(t, "x", cert.Subject.CommonName)

	_, err = parseCertificatePEM("garbage")
	var pemErr ErrStatusCertificatePEM
	assert.ErrorAs(t, err, &pemErr)

	_, err = parseCertificatePEM("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	assert.Error(t, err)
	assert.NotErrorAs(t, err, &pemErr, "a decodable block with bad DER is an x509 error")
}

func TestPlatformSRKHandleNote(t *testing.T) {
	def := platformSRKHandleNote(statusOptions{PlatformSRKHandle: defaultPlatformSRKHandle})
	assert.Contains(t, def, "default")
	assert.Contains(t, def, "--platform-srk-handle")

	explicit := platformSRKHandleNote(statusOptions{PlatformSRKHandle: 0x81000009, PlatformSRKHandleExplicit: true})
	assert.Contains(t, explicit, "--platform-srk-handle")
	assert.NotContains(t, explicit, "default")
}

func TestStatusColumns(t *testing.T) {
	restricted := true
	unrestricted := false
	cases := []struct {
		name   string
		obj    tpmObjectStatus
		handle string
		cert   string
		notes  string
	}{
		{"error wins", tpmObjectStatus{Name: "EK", HandlePresent: true, Error: "boom"}, "error", "n/a", "error: boom"},
		{"absent with role", tpmObjectStatus{Name: "IAK", Role: "Initial Attestation Key", Note: "run x"}, "absent", "n/a", "Initial Attestation Key; run x"},
		{"absent with probed handle", tpmObjectStatus{Name: "PlatformSRK", Role: "Platform SRK", Handle: "0x81000002", Note: "default"}, "absent", "n/a", "Platform SRK; 0x81000002; default"},
		{"present with cert format", tpmObjectStatus{Name: "EK", HandlePresent: true, CertPresent: true, CertFormat: "PEM"}, "present", "present (PEM)", ""},
		{"present restricted", tpmObjectStatus{Name: "IAK", HandlePresent: true, CertPresent: true, Handle: "0x81010002", Issuer: "ca", VerifiedTPMRestricted: &restricted}, "present", "present", "0x81010002; issuer ca; verifiedTPMRestricted"},
		{"present unrestricted", tpmObjectStatus{Name: "IAK", HandlePresent: true, CertPresent: true, Handle: "0x81010002", VerifiedTPMRestricted: &unrestricted}, "present", "present (" + verifiedTPMRestrictedNote + ")", "0x81010002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.handle, handleColumn(tc.obj))
			assert.Equal(t, tc.cert, certificateColumn(tc.obj))
			assert.Equal(t, tc.notes, notesColumn(tc.obj))
		})
	}
}

func TestShortErrAndIsAllZeros(t *testing.T) {
	assert.Equal(t, "short", shortErr(errors.New("short")))
	long := strings.Repeat("x", 200)
	got := shortErr(errors.New(long))
	assert.Len(t, got, 120)
	assert.True(t, strings.HasSuffix(got, "..."))
	assert.Equal(t, "empty response", shortErrOrNil(nil))
	assert.Equal(t, "e", shortErrOrNil(errors.New("e")))

	assert.True(t, isAllZeros("0000"))
	assert.True(t, isAllZeros(""))
	assert.False(t, isAllZeros("0a00"))
}

// TestNewStatusCommand_Flag: the flag exists with the platformd default
// and rejects a non-numeric handle.
func TestNewStatusCommand_Flag(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable}
	cmd := newStatusCommand(func() *cli.CommonFlags { return flags })
	assert.Equal(t, "status", cmd.Use)
	f := cmd.Flags().Lookup(platformSRKHandleFlag)
	require.NotNil(t, f)
	assert.Equal(t, "2164260866", f.DefValue, "0x81000002")

	cmd.SetArgs([]string{"--platform-srk-handle", "not-a-handle"})
	assert.Error(t, cmd.Execute())
}
