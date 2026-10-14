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
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// certifyClient answers Certify with a fixed attestation, or with err, and
// records the requests it received.
type certifyClient struct {
	platformv1.TPMServiceClient
	err      error
	requests []*platformv1.CertifyRequest
}

func (c *certifyClient) Certify(_ context.Context, req *platformv1.CertifyRequest, _ ...grpc.CallOption) (*platformv1.CertifyResponse, error) {
	c.requests = append(c.requests, req)
	if c.err != nil {
		return nil, c.err
	}
	return &platformv1.CertifyResponse{
		CertifyInfo:        []byte{0xAA},
		Signature:          []byte{0xBB},
		SignatureAlgorithm: "ECDSA-SHA256",
		AttestingKeyPublic: []byte{0xCC},
		AttestedKeyPublic:  []byte{0xDD},
		Nonce:              req.GetNonce(),
	}, nil
}

func TestRunCertifyWithClient_PrintsTheAttestation(t *testing.T) {
	client := &certifyClient{}
	base := newMockTPMBaseCommand(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON, NoColor: true}, client)

	err := runCertifyWithClient(base, &certifyOptions{Handle: "0x81000001", Password: "pw", Nonce: "0011"})

	require.NoError(t, err)
	require.Len(t, client.requests, 1)
	assert.Equal(t, uint32(0x81000001), client.requests[0].GetKeyHandle())
	assert.Equal(t, "pw", client.requests[0].GetKeyPassword())
	assert.Equal(t, []byte{0x00, 0x11}, client.requests[0].GetNonce())

	var printed map[string]string
	require.NoError(t, json.Unmarshal(base.output.Bytes(), &printed))
	assert.Equal(t, map[string]string{
		"key_handle":           "0x81000001",
		"certify_info":         "aa",
		"signature":            "bb",
		"signature_algorithm":  "ECDSA-SHA256",
		"attesting_key_public": "cc",
		"attested_key_public":  "dd",
		"nonce":                "0011",
	}, printed)
}

func TestRunCertifyWithClient_TableFormat(t *testing.T) {
	base := newMockTPMBaseCommand(&cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}, &certifyClient{})

	err := runCertifyWithClient(base, &certifyOptions{Handle: "2164260865"})

	require.NoError(t, err)
	assert.Contains(t, base.output.String(), "0x81000001")
	assert.Contains(t, base.output.String(), "ECDSA-SHA256")
}

func TestRunCertifyWithClient_Errors(t *testing.T) {
	tests := []struct {
		name    string
		format  cli.OutputFormat
		opts    *certifyOptions
		rpcErr  error
		wantErr error
		sent    bool
	}{
		{"handle not a number", cli.OutputFormatJSON, &certifyOptions{Handle: "srk"}, nil, ErrInvalidTPMHandle{}, false},
		{"nonce not hex", cli.OutputFormatJSON, &certifyOptions{Handle: "0x81000001", Nonce: "zz"}, nil, ErrInvalidCertifyNonce{}, false},
		{"daemon refuses", cli.OutputFormatJSON, &certifyOptions{Handle: "0x80000001"},
			status.Error(codes.InvalidArgument, "key handle 0x80000001 is not persistent"), ErrCertifyFailed{}, true},
		{"unknown output format", "invalid", &certifyOptions{Handle: "0x81000001"}, nil, cli.ErrInvalidOutputFormat{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &certifyClient{err: tt.rpcErr}
			base := newMockTPMBaseCommand(&cli.CommonFlags{OutputFormat: tt.format, NoColor: true}, client)

			err := runCertifyWithClient(base, tt.opts)

			require.Error(t, err)
			assert.IsType(t, tt.wantErr, err)
			assert.Equal(t, tt.sent, len(client.requests) == 1, "whether the daemon was asked")
		})
	}
}

func TestNewCertifyCommand_RequiresAHandle(t *testing.T) {
	cmd := newCertifyCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetArgs([]string{})
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	err := cmd.Execute()

	require.Error(t, err)
	assert.Contains(t, err.Error(), `"handle"`)
}
