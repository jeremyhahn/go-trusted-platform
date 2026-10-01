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

package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
)

func TestRecordAdmission_WritesDistinguishableEvents(t *testing.T) {
	st, err := store.NewFileStore(t.TempDir())
	require.NoError(t, err)
	svc := NewService(st)
	at := time.Unix(1_700_000_000, 0).UTC()

	require.NoError(t, svc.RecordAdmission(context.Background(), calleradmission.Decision{
		Admitted: true, Identity: "cp.example.internal", Names: []string{"cp.example.internal", "cp.example.io"},
		Strategy: calleradmission.StrategyReportingServers, Reason: calleradmission.ReasonAdmitted,
		Detail: "listed", RemoteAddr: "10.4.2.140:41000", At: at,
	}))
	require.NoError(t, svc.RecordAdmission(context.Background(), calleradmission.Decision{
		Admitted: false, Identity: "rogue.example.internal", Strategy: calleradmission.StrategyAllowlist,
		Reason: calleradmission.ReasonNotListed, Detail: "not listed", RemoteAddr: "[2001:db8::9]:1", At: at,
	}))
	require.NoError(t, svc.RecordAdmission(context.Background(), calleradmission.Decision{
		Admitted: false, Identity: "node-3.example.internal", Strategy: calleradmission.StrategyAnyAttested,
		Reason: calleradmission.ReasonNotAttested, Detail: "failed", RemoteAddr: "10.0.0.3:2", At: at,
	}))

	admitted, err := st.ListEvents(store.EventFilter{Kind: store.EventKindCallerAdmitted})
	require.NoError(t, err)
	require.Len(t, admitted, 1)
	assert.Equal(t, "cp.example.internal", admitted[0].CN)
	assert.Equal(t, "10.4.2.140", admitted[0].ClientIP)
	assert.Equal(t, "admitted", admitted[0].Outcome)
	assert.Equal(t, "reporting-servers", admitted[0].Metadata["strategy"])
	assert.Equal(t, "false", admitted[0].Metadata["security_relevant"])
	assert.Equal(t, "cp.example.internal,cp.example.io", admitted[0].Metadata["names"])
	assert.Equal(t, at, admitted[0].Timestamp)

	refused, err := st.ListEvents(store.EventFilter{Kind: store.EventKindCallerRefused})
	require.NoError(t, err)
	require.Len(t, refused, 2)
	byCN := map[string]*store.Event{}
	for _, e := range refused {
		byCN[e.CN] = e
	}
	assert.Equal(t, "false", byCN["rogue.example.internal"].Metadata["security_relevant"])
	assert.Equal(t, "not-listed", byCN["rogue.example.internal"].Metadata["reason"])
	assert.Equal(t, "2001:db8::9", byCN["rogue.example.internal"].ClientIP)
	assert.Equal(t, "true", byCN["node-3.example.internal"].Metadata["security_relevant"])
	assert.Equal(t, "not-attested", byCN["node-3.example.internal"].Metadata["reason"])
}

func TestRecordAdmission_FailsWithoutStore(t *testing.T) {
	var svc *Service
	require.Error(t, svc.RecordAdmission(context.Background(), calleradmission.Decision{}))
	require.Error(t, (&Service{}).RecordAdmission(context.Background(), calleradmission.Decision{}))
}

func TestClientIP(t *testing.T) {
	assert.Equal(t, "10.0.0.1", clientIP("10.0.0.1:5"))
	assert.Equal(t, "10.0.0.1", clientIP("10.0.0.1"))
	assert.Equal(t, "2001:db8::1", clientIP("[2001:db8::1]:5"))
	assert.Equal(t, "", clientIP(""))
}
