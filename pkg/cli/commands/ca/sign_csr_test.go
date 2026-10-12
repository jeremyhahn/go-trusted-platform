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

package ca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	casvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ca"
)

const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

// issueRecorder is a CA client that records the sign-CSR request it
// receives; a call to IssueCertificate panics on the nil embedded client.
type issueRecorder struct {
	platformv1.CAServiceClient
	req  *platformv1.SignCSRRequest
	resp *platformv1.IssueCertificateResponse
	err  error
}

func (r *issueRecorder) SignCSR(_ context.Context, in *platformv1.SignCSRRequest, _ ...grpc.CallOption) (*platformv1.IssueCertificateResponse, error) {
	r.req = in
	return r.resp, r.err
}

func issuedResponse() *platformv1.IssueCertificateResponse {
	return &platformv1.IssueCertificateResponse{
		Certificate: &platformv1.Certificate{Serial: "0a", Pem: []byte(testCertPEM)},
	}
}

func issuedResult() *casvc.IssueCertificateResult {
	return &casvc.IssueCertificateResult{Certificate: casvc.CertificateFromProto(issuedResponse().Certificate)}
}

func TestNewSignCSRCommand(t *testing.T) {
	cmd := newSignCSRCommand(testGetFlags())

	assert.Equal(t, "sign-csr [csr-file]", cmd.Use)
	for _, name := range []string{"valid-days", "out"} {
		assert.NotNil(t, cmd.Flags().Lookup(name), "flag --%s", name)
	}
	// The CA fixes the usage to codeSigning; the caller cannot ask for more.
	for _, name := range []string{"key-usage", "ext-key-usage"} {
		assert.Nil(t, cmd.Flags().Lookup(name), "flag --%s", name)
	}
	cmd.SetArgs([]string{})
	assert.ErrorContains(t, cmd.Execute(), "accepts 1 arg(s)")
}

// The CSR goes to the SignCSR RPC, which ca:write alone cannot reach, with
// only its validity beside it.
func TestSignCSR_SendsTheCSR(t *testing.T) {
	rec := &issueRecorder{resp: issuedResponse()}

	result, err := signCSR(context.Background(), casvc.NewClientFromGRPC(rec), []byte("csr"), signCSROptions{validDays: 30})
	require.NoError(t, err)

	require.NotNil(t, rec.req, "the CSR did not reach SignCSR")
	assert.Equal(t, "csr", rec.req.GetCsrPem())
	assert.Equal(t, int32(30), rec.req.GetValidDays())
	assert.Equal(t, testCertPEM, string(result.Certificate.Pem))
}

func TestSignCSR_Errors(t *testing.T) {
	cases := []struct {
		name string
		rec  *issueRecorder
		want error
	}{
		{"CA rejects the CSR", &issueRecorder{err: errors.New("invalid CSR")}, ErrIssueCertificateFailed{}},
		{"caller lacks ca:sign-csr", &issueRecorder{err: errors.New("permission denied: ca:sign-csr")}, ErrIssueCertificateFailed{}},
		{"no certificate", &issueRecorder{resp: &platformv1.IssueCertificateResponse{}}, ErrNoCertificateIssued{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signCSR(context.Background(), casvc.NewClientFromGRPC(tc.rec), []byte("csr"), signCSROptions{})
			assert.IsType(t, tc.want, err)
		})
	}
}

func TestPrintSignedCSR_StdoutIsThePEM(t *testing.T) {
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &out)

	err := printSignedCSR(printer, cli.OutputFormatTable, issuedResult(), "")
	require.NoError(t, err)
	assert.Equal(t, testCertPEM, out.String())
}

// JSON is the 'ca issue' result shape, so scripts read both alike.
func TestPrintSignedCSR_JSONIsTheIssueResult(t *testing.T) {
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatJSON, true, &out)

	require.NoError(t, printSignedCSR(printer, cli.OutputFormatJSON, issuedResult(), ""))
	var printed casvc.IssueCertificateResult
	require.NoError(t, json.Unmarshal(out.Bytes(), &printed))
	require.NotNil(t, printed.Certificate)
	assert.Equal(t, "0a", printed.Certificate.Serial)
	assert.Equal(t, testCertPEM, string(printed.Certificate.Pem))
}

func TestPrintSignedCSR_WritesOut(t *testing.T) {
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &out)
	path := filepath.Join(t.TempDir(), "fleet.pem")

	err := printSignedCSR(printer, cli.OutputFormatTable, issuedResult(), path)
	require.NoError(t, err)
	written, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, testCertPEM, string(written))
	assert.Contains(t, out.String(), "Certificate written to "+path)
}

func TestPrintSignedCSR_Errors(t *testing.T) {
	result := issuedResult()
	printer := cli.NewPrinterWithWriter(cli.OutputFormatTable, true, &bytes.Buffer{})

	err := printSignedCSR(printer, cli.OutputFormatTable, result, filepath.Join(t.TempDir(), "missing", "fleet.pem"))
	assert.IsType(t, ErrWriteCertificateFailed{}, err)

	err = printSignedCSR(printer, cli.OutputFormat("xml"), result, "")
	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}

func TestRunSignCSR_Errors(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}

	err := runSignCSR(flags, filepath.Join(t.TempDir(), "absent.csr"), signCSROptions{})
	assert.IsType(t, ErrReadCSRFailed{}, err)

	csrFile := filepath.Join(t.TempDir(), "fleet.csr")
	require.NoError(t, os.WriteFile(csrFile, []byte("csr"), 0o600))
	err = runSignCSR(flags, csrFile, signCSROptions{})
	assert.IsType(t, ErrDaemonConnectionRequired{}, err)
}
