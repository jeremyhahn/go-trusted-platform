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

package daemon

import (
	"context"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ekTPM answers the reads and the create that tpmek.Create makes.
type ekTPM struct {
	xkmssdk.TrustedPlatformModule
	template    tpm2.TPMTPublic
	persisted   bool
	createCalls int
}

func (t *ekTPM) EKAttributes() (*xkmssdk.KeyAttributes, error) {
	return &xkmssdk.KeyAttributes{
		TPMAttributes: &xkmssdk.TPMAttributes{Handle: 0x81010001, Template: t.template},
	}, nil
}

func (t *ekTPM) ReadHandle(tpm2.TPMHandle) (tpm2.TPM2BName, tpm2.TPMTPublic, error) {
	if t.persisted {
		return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, nil
	}
	return tpm2.TPM2BName{}, tpm2.TPMTPublic{}, tpm2.TPMRCHandle
}

func (t *ekTPM) CreateEK(*xkmssdk.KeyAttributes) error {
	t.createCalls++
	return nil
}

func createEKBoth(t *testing.T, tpm *ekTPM) (grpcErr, mcpErr error) {
	t.Helper()
	resp, grpcErr := newTPMGRPCServiceWith(tpm).CreateEK(context.Background(), &platformv1.CreateEKRequest{})
	if grpcErr == nil {
		assert.Equal(t, uint32(0x81010001), resp.GetHandle())
	}
	_, mcpErr = newMCPProviderWithTPM(tpm).TPMCreateEK(context.Background())
	return grpcErr, mcpErr
}

// TestTPMCreateEKParity_Creates: gRPC (and so Unix, embedded and daemon
// REST) and MCP create the configured EK through the same entry point.
func TestTPMCreateEKParity_Creates(t *testing.T) {
	tpm := &ekTPM{template: tpm2.RSAEKTemplate}

	grpcErr, mcpErr := createEKBoth(t, tpm)

	require.NoError(t, grpcErr)
	require.NoError(t, mcpErr)
	assert.Equal(t, 2, tpm.createCalls)
}

// TestTPMCreateEKParity_Refusals: an occupied EK handle is AlreadyExists
// and template-less EK attributes are FailedPrecondition on both, and
// neither reaches CreateEK (whose go-tpm marshal panics on a zero
// TPMT_PUBLIC).
func TestTPMCreateEKParity_Refusals(t *testing.T) {
	cases := map[string]struct {
		tpm  *ekTPM
		want codes.Code
	}{
		"persisted EK":   {tpm: &ekTPM{template: tpm2.RSAEKTemplate, persisted: true}, want: codes.AlreadyExists},
		"no EK template": {tpm: &ekTPM{}, want: codes.FailedPrecondition},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			grpcErr, mcpErr := createEKBoth(t, tc.tpm)

			assert.Equal(t, tc.want, status.Code(grpcErr), "gRPC")
			assert.Equal(t, tc.want, status.Code(mcpErr), "MCP")
			assert.Zero(t, tc.tpm.createCalls)
		})
	}
}
