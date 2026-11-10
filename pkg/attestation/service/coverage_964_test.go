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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/store"
)

// errStoreUnavailable is the typed failure failingStore answers with.
type errStoreUnavailable struct{ Op string }

func (e errStoreUnavailable) Error() string { return "store unavailable: " + e.Op }

// failingStore is a real FileStore whose manifest writes and listings fail,
// as a store on a full or unreadable disk does. Events still persist, so a
// test can assert that a failed write leaves no audit record behind.
type failingStore struct {
	*store.FileStore
}

func (f failingStore) PutManifest(*manifest.HostManifest) error {
	return errStoreUnavailable{Op: "PutManifest"}
}

func (f failingStore) ListManifests(store.ListFilter) ([]*manifest.HostManifest, error) {
	return nil, errStoreUnavailable{Op: "ListManifests"}
}

func newFailingService(t *testing.T) *Service {
	t.Helper()
	fs, err := store.NewFileStore(t.TempDir())
	require.NoError(t, err)
	return NewService(failingStore{FileStore: fs})
}

func putManifest(t *testing.T, svc *Service, id, host string, ts time.Time) {
	t.Helper()
	require.NoError(t, svc.Store().PutManifest(&manifest.HostManifest{ID: id, HostID: host, Timestamp: ts}))
}

// Evidence that a node cannot produce (no daemon TPM session for manifests,
// VMs or containers) is refused with a typed error naming the operation,
// never an empty result an appraiser could mistake for evidence (RFC 9334 §5.1).
func TestUnconfiguredCollectors_RefuseTyped(t *testing.T) {
	svc, _ := newVerdictService(t)
	ctx := context.Background()

	cases := []struct {
		op   string
		call func() (any, error)
	}{
		{"BuildManifest", func() (any, error) { return svc.BuildManifest(ctx, nil, []byte{1}, nil) }},
		{"CollectVMAttestation", func() (any, error) { return svc.CollectVMAttestation(ctx, "vm-1", nil, []byte{1}) }},
		{"CollectContainerAttestation", func() (any, error) { return svc.CollectContainerAttestation(ctx, "c-1") }},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			got, err := tc.call()
			var notConfigured ErrTPMSessionNotConfigured
			require.ErrorAs(t, err, &notConfigured)
			assert.Equal(t, tc.op, notConfigured.Op)
			assert.Contains(t, err.Error(), tc.op)
			assert.Nil(t, got)
		})
	}
}

func TestGetManifest_ReturnsTheStoredManifest(t *testing.T) {
	svc, _ := newVerdictService(t)
	putManifest(t, svc, "m-1", "host-a", time.Now().UTC())

	got, err := svc.GetManifest(context.Background(), "m-1")

	require.NoError(t, err)
	assert.Equal(t, "host-a", got.HostID)
}

func TestGetManifest_RefusesAnEmptyOrUnknownID(t *testing.T) {
	svc, _ := newVerdictService(t)

	_, err := svc.GetManifest(context.Background(), "")
	require.ErrorAs(t, err, &daemon.ErrAttestationManifestIDRequired{})

	_, err = svc.GetManifest(context.Background(), "absent")
	var notFound store.ErrManifestNotFound
	require.ErrorAs(t, err, &notFound)
	assert.Equal(t, "absent", notFound.ID)
}

func TestListManifests_AppliesTheFilter(t *testing.T) {
	svc, _ := newVerdictService(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	putManifest(t, svc, "a-old", "host-a", base.Add(-2*time.Hour))
	putManifest(t, svc, "a-new", "host-a", base)
	putManifest(t, svc, "b-new", "host-b", base)

	cases := []struct {
		name   string
		filter *daemon.ListManifestsFilter
		want   []string
	}{
		{"nil filter lists all", nil, []string{"a-old", "a-new", "b-new"}},
		{"host", &daemon.ListManifestsFilter{HostID: "host-a"}, []string{"a-old", "a-new"}},
		{"start time", &daemon.ListManifestsFilter{StartTime: base.Add(-time.Hour).Unix()}, []string{"a-new", "b-new"}},
		{"end time", &daemon.ListManifestsFilter{EndTime: base.Add(-time.Hour).Unix()}, []string{"a-old"}},
		{"limit", &daemon.ListManifestsFilter{HostID: "host-a", Limit: 1}, []string{"a-new"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, total, err := svc.ListManifests(context.Background(), tc.filter)
			require.NoError(t, err)
			ids := make([]string, 0, len(got))
			for _, m := range got {
				ids = append(ids, m.ID)
			}
			assert.ElementsMatch(t, tc.want, ids)
			assert.Equal(t, len(tc.want), total)
		})
	}
}

func TestListManifests_SurfacesTheStoreError(t *testing.T) {
	svc := newFailingService(t)

	got, total, err := svc.ListManifests(context.Background(), nil)

	require.ErrorAs(t, err, &errStoreUnavailable{})
	assert.Nil(t, got)
	assert.Zero(t, total)
}

func TestDeleteManifest_RemovesAndAudits(t *testing.T) {
	svc, _ := newVerdictService(t)
	putManifest(t, svc, "m-1", "host-a", time.Now().UTC())

	require.NoError(t, svc.DeleteManifest(context.Background(), "m-1"))

	_, err := svc.GetManifest(context.Background(), "m-1")
	require.ErrorAs(t, err, &store.ErrManifestNotFound{})
	events, err := svc.Store().ListEvents(store.EventFilter{ManifestID: "m-1"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, store.EventKindManifestDeleted, events[0].Kind)
}

func TestDeleteManifest_RefusesAnEmptyOrUnknownIDWithoutAuditing(t *testing.T) {
	svc, _ := newVerdictService(t)

	require.ErrorAs(t, svc.DeleteManifest(context.Background(), ""), &daemon.ErrAttestationManifestIDRequired{})
	require.ErrorAs(t, svc.DeleteManifest(context.Background(), "absent"), &store.ErrManifestNotFound{})

	events, err := svc.Store().ListEvents(store.EventFilter{Kind: store.EventKindManifestDeleted})
	require.NoError(t, err)
	assert.Empty(t, events)
}

// A failed appraisal of manifest evidence is a rejected verdict with the
// failing claim named, recorded as a rejection event (RFC 9334 §5.1, §8.4).
func TestVerifyManifest_RejectsEvidenceThatFailsAppraisal(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(m *manifest.HostManifest)
		nonce    []byte
		pcrs     map[int][]byte
		wantErr  string
		checkRes func(t *testing.T, r *manifest.VerificationResult)
	}{
		{
			name:    "nonce of another length",
			nonce:   []byte{1, 2},
			wantErr: "manifest nonce does not match the expected value",
			checkRes: func(t *testing.T, r *manifest.VerificationResult) {
				assert.False(t, r.NonceValid)
			},
		},
		{
			name:    "nonce of the same length",
			nonce:   []byte{1, 2, 4},
			wantErr: "manifest nonce does not match the expected value",
			checkRes: func(t *testing.T, r *manifest.VerificationResult) {
				assert.False(t, r.NonceValid)
			},
		},
		{
			name: "pcr mismatch",
			mutate: func(m *manifest.HostManifest) {
				m.Host = &manifest.HostAttestation{PCRs: []manifest.PCRValue{
					{Index: 0, Value: []byte{0xaa}},
					{Index: 7, Value: []byte{0xbb}},
				}}
			},
			pcrs:    map[int][]byte{7: {0xcc}},
			wantErr: "PCR[7] mismatch",
			checkRes: func(t *testing.T, r *manifest.VerificationResult) {
				assert.False(t, r.HostAttestationValid)
				assert.True(t, r.NonceValid)
			},
		},
		{
			name:    "stale manifest",
			mutate:  func(m *manifest.HostManifest) { m.Timestamp = time.Now().Add(-25 * time.Hour) },
			wantErr: "manifest is older than 24 hours",
			checkRes: func(t *testing.T, r *manifest.VerificationResult) {
				assert.False(t, r.TimestampValid)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newVerdictService(t)
			m := storedManifest()
			if tc.mutate != nil {
				tc.mutate(m)
			}

			res, err := svc.VerifyManifest(context.Background(), m, nil, tc.nonce, nil, tc.pcrs)

			require.NoError(t, err)
			assert.Equal(t, manifest.VerificationStatusFailed, res.Status)
			assert.Equal(t, []string{tc.wantErr}, res.Errors)
			tc.checkRes(t, res)
			events, err := svc.Store().ListEvents(store.EventFilter{HostID: "host-a"})
			require.NoError(t, err)
			require.Len(t, events, 1)
			assert.Equal(t, store.EventKindManifestRejected, events[0].Kind)
			assert.Equal(t, "rejected", events[0].Outcome)
			assert.Contains(t, events[0].Reason, tc.wantErr)
		})
	}
}

func TestVerifyManifest_AcceptsMatchingPCRsAndReportsAMissingMerkleRoot(t *testing.T) {
	svc, _ := newVerdictService(t)
	m := storedManifest()
	m.MerkleRoot = nil
	m.Host = &manifest.HostAttestation{PCRs: []manifest.PCRValue{{Index: 7, Value: []byte{0xbb}}}}

	res, err := svc.VerifyManifest(context.Background(), m, nil, nil, nil, map[int][]byte{7: {0xbb}})

	require.NoError(t, err)
	assert.Equal(t, manifest.VerificationStatusVerified, res.Status)
	assert.True(t, res.HostAttestationValid)
	assert.False(t, res.MerkleRootValid)
}

func TestVerifyManifest_RequiresAManifest(t *testing.T) {
	svc, _ := newVerdictService(t)

	res, err := svc.VerifyManifest(context.Background(), nil, nil, nil, nil, nil)

	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Equal(t, "attestation/service: manifest is required", err.Error())
	assert.Nil(t, res)
}

// A quote whose PCR values differ from the reference values is a rejected
// verdict naming the PCR, not a call error (RFC 9334 §5.1, RFC 9683 §4).
func TestVerifyQuote_RejectsAPCRMismatch(t *testing.T) {
	svc := newQuoteService(t, newFakeQuoter(t))
	quote, ak := boundQuote(t, svc, []byte("verifier-chosen-nonce-0123456789"), []byte("connection-A-exporter-0123456789"))
	require.NotEmpty(t, quote.PCRValues)
	reference := []manifest.PCRValue{{Index: quote.PCRValues[0].Index, Value: []byte("not-the-measured-value-000000000")}}

	res, err := svc.VerifyQuote(context.Background(), quote, ak, nil, reference)

	require.NoError(t, err)
	assert.False(t, res.Verified)
	assert.Contains(t, res.Message, "PCR mismatch")
	assert.Equal(t, quote.PCRValues, res.ActualPCRs)
}

func TestVerifyQuote_RequiresAQuoteAndAKey(t *testing.T) {
	svc := newQuoteService(t, nil)

	_, err := svc.VerifyQuote(context.Background(), nil, []byte{1}, nil, nil)
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Equal(t, "attestation/service: quote is required", msgErr.Error())

	_, err = svc.VerifyQuote(context.Background(), &daemon.QuoteResult{}, nil, nil, nil)
	require.ErrorAs(t, err, &msgErr)
	assert.Equal(t, "attestation/service: AK public key is required", msgErr.Error())
}

func TestCaptureFromEnrollment_StoresTheManifestAndAudits(t *testing.T) {
	svc, _ := newVerdictService(t)
	in := EnrollmentInput{
		CN:            "node-1",
		ProductModel:  "model-x",
		ProductSerial: "sn-1",
		ClientIP:      "192.0.2.10",
		EventLog:      []byte("eventlog"),
		QuoteData:     []byte("quote"),
		Signature:     []byte("sig"),
		Nonce:         []byte{1, 2, 3},
		PCRs:          map[int][]byte{0: {0xa0}, 7: {0xa7}},
		PCRDigest:     []byte("digest"),
		MerkleRoot:    []byte{9},
		AKPublicKey:   []byte("ak"),
		IDevIDCert:    []byte("idevid"),
	}

	m, err := svc.CaptureFromEnrollment(in)

	require.NoError(t, err)
	assert.Regexp(t, `^node-1-\d{8}T\d{6}\.\d{9}Z$`, m.ID)
	assert.Equal(t, "node-1", m.HostID)
	assert.Equal(t, "model-x", m.Metadata["product_model"])
	assert.Equal(t, "sn-1", m.Metadata["serial"])
	assert.Equal(t, "192.0.2.10", m.Metadata["client_ip"])
	assert.ElementsMatch(t, []manifest.PCRValue{{Index: 0, Value: []byte{0xa0}}, {Index: 7, Value: []byte{0xa7}}}, m.Host.PCRs)
	assert.Equal(t, []byte("ak"), m.Host.AKPublicKey)
	assert.Equal(t, []byte("idevid"), m.Host.IDevIDCertificate)

	stored, err := svc.GetManifest(context.Background(), m.ID)
	require.NoError(t, err)
	assert.Equal(t, m.Nonce, stored.Nonce)

	events, err := svc.Store().ListEvents(store.EventFilter{ManifestID: m.ID})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, store.EventKindManifestCaptured, events[0].Kind)
	assert.Equal(t, "captured", events[0].Outcome)
	assert.Equal(t, "8", events[0].Metadata["event_log_bytes"])
	assert.Equal(t, "2", events[0].Metadata["pcr_count"])
}

func TestCaptureFromEnrollment_RefusesWithoutACNOrAStore(t *testing.T) {
	svc, _ := newVerdictService(t)
	_, err := svc.CaptureFromEnrollment(EnrollmentInput{})
	var msgErr *MessageError
	require.ErrorAs(t, err, &msgErr)
	assert.Equal(t, "attestation/service: enrollment CN is required", msgErr.Error())

	failing := newFailingService(t)
	m, err := failing.CaptureFromEnrollment(EnrollmentInput{CN: "node-1"})
	require.ErrorAs(t, err, &errStoreUnavailable{})
	assert.Nil(t, m)
	events, err := failing.Store().ListEvents(store.EventFilter{HostID: "node-1"})
	require.NoError(t, err)
	assert.Empty(t, events, "a manifest that was not stored must not be audited as captured")
}

func TestRecordEnrollEvent_PersistsTheEvent(t *testing.T) {
	svc, _ := newVerdictService(t)

	err := svc.RecordEnrollEvent(store.EventKindEnrollFailure, "node-1", "192.0.2.10", "refused", "bad csr", map[string]string{"k": "v"})

	require.NoError(t, err)
	events, err := svc.Store().ListEvents(store.EventFilter{HostID: "node-1"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	e := events[0]
	assert.Equal(t, store.EventKindEnrollFailure, e.Kind)
	assert.Equal(t, "node-1", e.CN)
	assert.Equal(t, "192.0.2.10", e.ClientIP)
	assert.Equal(t, "refused", e.Outcome)
	assert.Equal(t, "bad csr", e.Reason)
	assert.Equal(t, map[string]string{"k": "v"}, e.Metadata)
}

func TestRecordEnrollEvent_SurfacesTheStoreError(t *testing.T) {
	fs, err := store.NewFileStore(t.TempDir())
	require.NoError(t, err)
	svc := NewService(eventFailingStore{FileStore: fs})

	err = svc.RecordEnrollEvent(store.EventKindEnrollSuccess, "node-1", "", "ok", "", nil)

	require.ErrorAs(t, err, &errStoreUnavailable{})
}

// eventFailingStore fails event appends, as a store on a full disk does.
type eventFailingStore struct {
	*store.FileStore
}

func (f eventFailingStore) PutEvent(*store.Event) error {
	return errStoreUnavailable{Op: "PutEvent"}
}
