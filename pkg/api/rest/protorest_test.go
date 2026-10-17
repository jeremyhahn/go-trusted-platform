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

package rest

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestDecodeProtoParams(t *testing.T) {
	p256 := platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256
	accepts := []struct {
		name   string
		params url.Values
		msg    proto.Message
		want   proto.Message
	}{
		{"a hex handle", url.Values{"handle": {"0x81000002"}}, &platformv1.GetSRKRequest{}, &platformv1.GetSRKRequest{Handle: srkHandle}},
		{"a decimal handle", url.Values{"handle": {srkHandleJS}}, &platformv1.GetSRKRequest{}, &platformv1.GetSRKRequest{Handle: srkHandle}},
		{"an enum by name", url.Values{"algorithm": {"KEY_ALGORITHM_ECDSA_P256"}}, &platformv1.GetEKRequest{}, &platformv1.GetEKRequest{Algorithm: p256}},
		{"an enum by number", url.Values{"algorithm": {"4"}}, &platformv1.GetEKRequest{}, &platformv1.GetEKRequest{Algorithm: p256}},
		{"a repeated field once per element", url.Values{"indices": {"0", "7"}}, &platformv1.GetPCRsRequest{}, &platformv1.GetPCRsRequest{Indices: []uint32{0, 7}}},
		{"a field's JSON name", url.Values{"numBytes": {"32"}}, &platformv1.GetRandomRequest{}, &platformv1.GetRandomRequest{NumBytes: 32}},
		{"a field's proto name", url.Values{"num_bytes": {"32"}}, &platformv1.GetRandomRequest{}, &platformv1.GetRandomRequest{NumBytes: 32}},
		{"a bool", url.Values{"confirm": {"true"}}, &platformv1.TPMClearRequest{}, &platformv1.TPMClearRequest{Confirm: true}},
		{"a string", url.Values{"format": {"json"}}, &platformv1.GetEventLogRequest{}, &platformv1.GetEventLogRequest{Format: "json"}},
		{"no parameters", url.Values{}, &platformv1.GetEKRequest{}, &platformv1.GetEKRequest{}},
		{
			"a uint64 wider than 32 bits", url.Values{"invitation_id": {"18446744073709551615"}},
			&platformv1.GetInvitationRequest{}, &platformv1.GetInvitationRequest{InvitationId: 18446744073709551615},
		},
		{
			"a nested message's fields by dotted name", url.Values{"pagination.page": {"2"}, "pagination.page_size": {"25"}},
			&platformv1.ListVMsRequest{}, &platformv1.ListVMsRequest{Pagination: &platformv1.PaginationRequest{Page: 2, PageSize: 25}},
		},
		{
			"a nested repeated field by JSON names", url.Values{"selector.matchExpressions": {"env=prod", "tier!=db"}},
			&platformv1.ListVMsRequest{}, &platformv1.ListVMsRequest{Selector: &platformv1.LabelSelector{MatchExpressions: []string{"env=prod", "tier!=db"}}},
		},
		{
			"a string map entry keyed after the field", url.Values{"selector.matchLabels.app.kubernetes.io/name": {"web"}},
			&platformv1.ListContainersRequest{}, &platformv1.ListContainersRequest{Selector: &platformv1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "web"}}},
		},
		{
			"repeated enums by name", url.Values{"states": {"VM_STATE_RUNNING", "VM_STATE_PAUSED"}},
			&platformv1.ListVMsRequest{}, &platformv1.ListVMsRequest{States: []platformv1.VMState{platformv1.VMState_VM_STATE_RUNNING, platformv1.VMState_VM_STATE_PAUSED}},
		},
	}
	for _, tc := range accepts {
		t.Run("accepts "+tc.name, func(t *testing.T) {
			require.NoError(t, decodeProtoParams(tc.params, tc.msg.ProtoReflect()))
			assert.True(t, proto.Equal(tc.want, tc.msg), "want %v, got %v", tc.want, tc.msg)
		})
	}

	refusals := []struct {
		name   string
		params url.Values
		msg    proto.Message
		want   ErrInvalidQueryParameter
	}{
		{
			name: "an unknown parameter", params: url.Values{"colour": {"red"}}, msg: &platformv1.GetEKRequest{},
			want: ErrInvalidQueryParameter{Name: "colour", Value: "red", Reason: "not a field of platform.v1.GetEKRequest"},
		},
		{
			name: "a map field without a key", params: url.Values{"properties": {"a"}}, msg: &platformv1.TPMInfoResponse{},
			want: ErrInvalidQueryParameter{Name: "properties", Value: "a", Reason: "a map parameter names its key: properties.<key>"},
		},
		{
			name: "a map entry given twice", params: url.Values{"properties.vendor": {"a", "b"}}, msg: &platformv1.TPMInfoResponse{},
			want: ErrInvalidQueryParameter{Name: "properties.vendor", Value: "a,b", Reason: "given more than once"},
		},
		{
			name: "a map keyed by a number", params: url.Values{"values.7": {"x"}}, msg: &platformv1.PCRBaseline{},
			want: ErrInvalidQueryParameter{Name: "values.7", Value: "x", Reason: "only a map of string to string can be a URL parameter"},
		},
		{
			name: "a map of messages", params: url.Values{"fields.x": {"1"}}, msg: &structpb.Struct{},
			want: ErrInvalidQueryParameter{Name: "fields.x", Value: "1", Reason: "only a map of string to string can be a URL parameter"},
		},
		{
			name: "an unknown field of a nested message", params: url.Values{"pagination.colour": {"red"}}, msg: &platformv1.ListVMsRequest{},
			want: ErrInvalidQueryParameter{Name: "pagination.colour", Value: "red", Reason: "not a field of platform.v1.PaginationRequest"},
		},
		{
			name: "a dotted name through a scalar", params: url.Values{"id.x": {"1"}}, msg: &platformv1.GetVMRequest{},
			want: ErrInvalidQueryParameter{Name: "id.x", Value: "1", Reason: "id has no fields"},
		},
		{
			name: "a dotted name through a repeated message", params: url.Values{"env.name": {"A"}}, msg: &platformv1.ExecContainerRequest{},
			want: ErrInvalidQueryParameter{Name: "env.name", Value: "A", Reason: "env has no fields"},
		},
		{
			name: "a scalar given twice", params: url.Values{"handle": {"1", "2"}}, msg: &platformv1.GetEKRequest{},
			want: ErrInvalidQueryParameter{Name: "handle", Value: "1,2", Reason: "given more than once"},
		},
		{
			name: "a message field", params: url.Values{"attributes": {"x"}}, msg: &platformv1.CreateEKRequest{},
			want: ErrInvalidQueryParameter{Name: "attributes", Value: "x", Reason: "a message field cannot be a URL parameter"},
		},
		{
			name: "a bytes field", params: url.Values{"data": {"x"}}, msg: &platformv1.SealRequest{},
			want: ErrInvalidQueryParameter{Name: "data", Value: "x", Reason: "a bytes field cannot be a URL parameter"},
		},
		{
			name: "a negative handle", params: url.Values{"handle": {"-1"}}, msg: &platformv1.GetSRKRequest{},
			want: ErrInvalidQueryParameter{Name: "handle", Value: "-1", Reason: "not a valid uint32"},
		},
		{
			name: "a handle wider than 32 bits", params: url.Values{"handle": {"0x100000000"}}, msg: &platformv1.GetSRKRequest{},
			want: ErrInvalidQueryParameter{Name: "handle", Value: "0x100000000", Reason: "not a valid uint32"},
		},
		{
			name: "a negative uint64", params: url.Values{"invitation_id": {"-1"}}, msg: &platformv1.GetInvitationRequest{},
			want: ErrInvalidQueryParameter{Name: "invitation_id", Value: "-1", Reason: "not a valid uint64"},
		},
		{
			name: "a uint64 past 64 bits", params: url.Values{"invitation_id": {"18446744073709551616"}}, msg: &platformv1.GetInvitationRequest{},
			want: ErrInvalidQueryParameter{Name: "invitation_id", Value: "18446744073709551616", Reason: "not a valid uint64"},
		},
		{
			name: "an unknown enum name", params: url.Values{"algorithm": {"KEY_ALGORITHM_ROT13"}}, msg: &platformv1.GetEKRequest{},
			want: ErrInvalidQueryParameter{Name: "algorithm", Value: "KEY_ALGORITHM_ROT13", Reason: "not a valid enum"},
		},
		{
			name: "an enum number with no value", params: url.Values{"algorithm": {"99"}}, msg: &platformv1.GetEKRequest{},
			want: ErrInvalidQueryParameter{Name: "algorithm", Value: "99", Reason: "not a valid enum"},
		},
		{
			name: "a bool that is not one", params: url.Values{"confirm": {"maybe"}}, msg: &platformv1.TPMClearRequest{},
			want: ErrInvalidQueryParameter{Name: "confirm", Value: "maybe", Reason: "not a valid bool"},
		},
		{
			name: "a bad element of a repeated field", params: url.Values{"indices": {"0", "seven"}}, msg: &platformv1.GetPCRsRequest{},
			want: ErrInvalidQueryParameter{Name: "indices", Value: "seven", Reason: "not a valid uint32"},
		},
	}
	for _, tc := range refusals {
		t.Run("refuses "+tc.name, func(t *testing.T) {
			err := decodeProtoParams(tc.params, tc.msg.ProtoReflect())

			var got ErrInvalidQueryParameter
			require.ErrorAs(t, err, &got)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProtoRESTErrors(t *testing.T) {
	t.Run("ErrInvalidQueryParameter", func(t *testing.T) {
		err := ErrInvalidQueryParameter{Name: "handle", Value: "-1", Reason: "not a valid uint32"}
		assert.Equal(t, `invalid query parameter handle="-1": not a valid uint32`, err.Error())
	})

	t.Run("ErrResponseEncoding", func(t *testing.T) {
		cause := errors.New("invalid UTF-8")
		err := ErrResponseEncoding{Cause: cause}
		assert.Equal(t, "encode_response failed: invalid UTF-8", err.Error())
		assert.ErrorIs(t, err, cause)
	})
}

func TestProtoResponderWriteJSON(t *testing.T) {
	out := protoResponder{logger: slog.Default()}

	t.Run("writes a JSON response", func(t *testing.T) {
		rec := httptest.NewRecorder()

		out.writeJSON(rec, http.StatusOK, map[string]string{"key": "value"})

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		var body map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "value", body["key"])
	})

	t.Run("a value that cannot be encoded still sends the status", func(t *testing.T) {
		rec := httptest.NewRecorder()

		out.writeJSON(rec, http.StatusAccepted, make(chan int))

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.Empty(t, rec.Body.String())
	})
}

func TestProtoResponderWriteError(t *testing.T) {
	t.Run("writes the error envelope", func(t *testing.T) {
		rec := httptest.NewRecorder()

		protoResponder{logger: slog.Default()}.writeError(rec, http.StatusServiceUnavailable, ErrTPMServiceNotAvailable{})

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		var body ErrorResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "TPM service not available", body.Error)
		assert.Equal(t, http.StatusServiceUnavailable, body.Code)
	})

	t.Run("an unmapped status error is 500", func(t *testing.T) {
		rec := httptest.NewRecorder()

		protoResponder{logger: slog.Default()}.writeStatusError(rec, errors.New("not a status error"))

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "not a status error")
	})
}
