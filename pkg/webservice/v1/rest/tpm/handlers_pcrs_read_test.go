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
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestGetPCRs_RejectsAnUnreadableSelection pins that POST /tpm/pcrs refuses
// a PCR index above 23 or a bank outside the PCRBank enum with a 400 before
// the request reaches the TPM, and still forwards a valid selection.
func TestGetPCRs_RejectsAnUnreadableSelection(t *testing.T) {
	rejected := []struct {
		name string
		body string
	}{
		{"index above 23", `{"indices":[24]}`},
		{"index at uint32 max", `{"indices":[0,4294967295]}`},
		{"unknown numeric bank", `{"bank":99}`},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			srv := &forwardingServer{resp: &platformv1.GetPCRsResponse{}}
			rec := serveRoute(t, srv, http.MethodPost, "/api/v1/tpm/pcrs", tc.body)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Nil(t, srv.got, "the RPC must not be reached")
		})
	}

	t.Run("valid selection is forwarded", func(t *testing.T) {
		srv := &forwardingServer{resp: &platformv1.GetPCRsResponse{}}
		rec := serveRoute(t, srv, http.MethodPost, "/api/v1/tpm/pcrs",
			`{"indices":[0,23],"bank":"PCR_BANK_SHA384"}`)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		want := &platformv1.GetPCRsRequest{
			Indices: []uint32{0, 23},
			Bank:    platformv1.PCRBank_PCR_BANK_SHA384,
		}
		require.NotNil(t, srv.got)
		assert.True(t, proto.Equal(want, srv.got), "forwarded %v, want %v", srv.got, want)
	})
}
