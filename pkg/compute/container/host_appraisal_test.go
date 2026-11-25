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

package container

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// A PCR divergence from a named reference value on a baseline register quarantines the host.
func TestFleetContainerAttestor_ReferenceValueDivergenceQuarantines(t *testing.T) {
	f := newFleetFixture()
	appraisal := &orchestration.HostAppraisalError{
		Image:                "img",
		ReferenceValues:      "agent-host",
		CryptographicFailure: true,
		Failures: []orchestration.HostAppraisalFailure{{
			Check:   "baseline",
			Outcome: "forged",
			Reason:  "quoted PCR value not admitted",
			PCRs: []orchestration.PCRDivergence{{
				Index:    7,
				Expected: [][]byte{goldenPCR7},
				Quoted:   []byte{0xde, 0xad},
			}},
		}},
	}
	f.inner.resp, f.inner.err = nil, upstreamError{cause: appraisal}

	resp, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{
		Image: "img", DeviceID: "42", ReferenceValues: "agent-host",
	})
	assert.Nil(t, resp)
	var drift ErrFleetHostDrift
	require.ErrorAs(t, err, &drift)
	assert.Equal(t, uint32(7), drift.Index)
	assert.NoError(t, drift.QuarantineErr)
	var got *orchestration.HostAppraisalError
	assert.ErrorAs(t, err, &got, "the upstream appraisal stays reachable")
	require.NotNil(t, f.inner.got)
	assert.Equal(t, "agent-host", f.inner.got.ReferenceValues, "the named reference values reach the appraiser")

	require.Len(t, f.verdicts.verdicts, 1)
	assert.False(t, f.verdicts.verdicts[0].Passed)
	require.Len(t, f.registry.saved, 1)
	assert.Equal(t, entities.DeviceStateQuarantined, f.registry.saved[0].State)
}
