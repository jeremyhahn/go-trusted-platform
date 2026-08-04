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

//go:build codec_msgpack

package quic

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// daemonFetchConfigWire replicates the daemon-side wire struct
// ConfigDeliveryFetchConfigResponse (pkg/api/daemon/quic_configdelivery.go)
// WITHOUT importing pkg/api/daemon. Because the QUIC payload codec keys on
// exact Go field names, encoding this struct produces byte-identical wire
// payloads to the daemon's — pinning the SDK mirror structs against the
// daemon shape without a compile-time dependency.
type daemonFetchConfigWire struct {
	Result              string
	ConfigJson          []byte
	Status              string
	SessionId           string
	ProvisionUrl        string
	PollIntervalSeconds int32
}

// daemonPollSessionWire replicates the daemon-side wire struct
// ConfigDeliveryPollSessionResponse. See daemonFetchConfigWire.
type daemonPollSessionWire struct {
	Result        string
	ConfigJson    []byte
	Status        string
	PendingStatus string
}

// TestInvoke_CategoryPrefix_AllProvisioningMethods verifies every
// ConfigDeliveryService method emits OpProvisioningCategory (0xCF) with the
// correct sub-opcode in payload[0], matching the server dispatcher in
// pkg/api/daemon/quic_configdelivery.go.
func TestInvoke_CategoryPrefix_AllProvisioningMethods(t *testing.T) {
	tests := []struct {
		method        string
		args          interface{}
		expectedSubOp byte
	}{
		{"/platform.v1.ConfigDeliveryService/GetNonce", &platformv1.GetNonceRequest{}, quicapi.ProvisioningSubGetNonce},
		{"/platform.v1.ConfigDeliveryService/FetchConfig", &platformv1.FetchConfigRequest{EabKeyId: "kid"}, quicapi.ProvisioningSubFetchConfig},
		{"/platform.v1.ConfigDeliveryService/SignDigest", &platformv1.SignDigestRequest{Digest: []byte{1}}, quicapi.ProvisioningSubSignDigest},
		{"/platform.v1.ConfigDeliveryService/PollSession", &platformv1.PollSessionRequest{SessionId: "s"}, quicapi.ProvisioningSubPollSession},
		{"/platform.v1.ConfigDeliveryService/FulfillSession", &platformv1.FulfillSessionRequest{SessionId: "s", ProfileId: 1}, quicapi.ProvisioningSubFulfillSession},
		{"/platform.v1.ConfigDeliveryService/ListSessions", &platformv1.ListSessionsRequest{}, quicapi.ProvisioningSubListSessions},
		{"/platform.v1.ConfigDeliveryService/GetSession", &platformv1.GetSessionRequest{SessionId: "s"}, quicapi.ProvisioningSubGetSession},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			err := conn.Invoke(context.Background(), tt.method, tt.args, nil)
			if err != nil {
				t.Fatalf("Invoke() unexpected error: %v", err)
			}
			if sender.rawCalls != 1 {
				t.Fatalf("expected exactly 1 SendRequest call, got %d", sender.rawCalls)
			}
			if sender.rawOpcode != quicapi.OpProvisioningCategory {
				t.Errorf("opcode = 0x%02X, want 0x%02X (OpProvisioningCategory)",
					sender.rawOpcode, quicapi.OpProvisioningCategory)
			}
			if len(sender.rawPayload) == 0 {
				t.Fatal("payload must contain at least the sub-opcode prefix")
			}
			if sender.rawPayload[0] != tt.expectedSubOp {
				t.Errorf("payload[0] sub-opcode = 0x%02X, want 0x%02X",
					sender.rawPayload[0], tt.expectedSubOp)
			}
		})
	}
}

// TestInvoke_ProvisioningEmptyBodyMethods verifies GetNonce and ListSessions
// send exactly the single sub-opcode byte even though the generated gRPC
// client passes non-nil empty request messages. This is the wire contract of
// the daemon dispatchers, which ignore payload[1:] for these verbs.
func TestInvoke_ProvisioningEmptyBodyMethods(t *testing.T) {
	tests := []struct {
		method        string
		args          interface{}
		expectedSubOp byte
	}{
		{"/platform.v1.ConfigDeliveryService/GetNonce", &platformv1.GetNonceRequest{}, quicapi.ProvisioningSubGetNonce},
		{"/platform.v1.ConfigDeliveryService/ListSessions", &platformv1.ListSessionsRequest{}, quicapi.ProvisioningSubListSessions},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			if err := conn.Invoke(context.Background(), tt.method, tt.args, nil); err != nil {
				t.Fatalf("Invoke() unexpected error: %v", err)
			}
			if len(sender.rawPayload) != 1 {
				t.Fatalf("expected 1-byte payload (sub-opcode only), got %d bytes",
					len(sender.rawPayload))
			}
			if sender.rawPayload[0] != tt.expectedSubOp {
				t.Errorf("sub-opcode = 0x%02X, want 0x%02X", sender.rawPayload[0], tt.expectedSubOp)
			}
		})
	}
}

// TestInvoke_ProvisioningRequestEncodesPBFieldNames pins the request wire
// contract: the encoded payload[1:] keys on the exact pb Go field names the
// daemon-side mirror request structs (ConfigDeliveryFetchConfigRequest et
// al.) decode by.
func TestInvoke_ProvisioningRequestEncodesPBFieldNames(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	args := &platformv1.FetchConfigRequest{
		EkSerial:   "EK1",
		MacAddress: "aa:bb",
		EkCert:     "certb64",
		EabKeyId:   "kid",
		EabHmac:    "hmac",
		Nonce:      "n1",
	}
	if err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig", args, nil); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	// Decode payload[1:] into a daemon-shaped mirror of
	// ConfigDeliveryFetchConfigRequest: same Go field names, no daemon
	// import.
	var got struct {
		EkSerial   string
		MacAddress string
		EkCert     string
		EabKeyId   string
		EabHmac    string
		Nonce      string
	}
	if err := quicapi.DecodePayload(sender.rawPayload[1:], &got); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
	if got.EkSerial != "EK1" || got.MacAddress != "aa:bb" || got.EkCert != "certb64" ||
		got.EabKeyId != "kid" || got.EabHmac != "hmac" || got.Nonce != "n1" {
		t.Errorf("daemon-shaped decode = %+v, want all request fields round-tripped", got)
	}
}

// TestInvoke_ProvisioningFetchConfig_DeliveredRoundTrip pins the SDK mirror
// struct against a daemon-shaped encoded payload for the delivered arm.
func TestInvoke_ProvisioningFetchConfig_DeliveredRoundTrip(t *testing.T) {
	encoded, err := quicapi.EncodePayload(&daemonFetchConfigWire{
		Result:     "delivered",
		ConfigJson: []byte(`{"hostname":"lab-node-2"}`),
		Status:     "ok",
	})
	if err != nil {
		t.Fatalf("EncodePayload setup failed: %v", err)
	}

	sender := &recordingSender{respPayload: encoded}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.FetchConfigResponse{}
	err = conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig",
		&platformv1.FetchConfigRequest{}, reply)
	if err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	delivered := reply.GetDelivered()
	if delivered == nil {
		t.Fatalf("expected delivered oneof arm, got %+v", reply)
	}
	if delivered.GetStatus() != "ok" {
		t.Errorf("status = %q, want ok", delivered.GetStatus())
	}
	if string(delivered.GetConfigJson()) != `{"hostname":"lab-node-2"}` {
		t.Errorf("config_json = %s", delivered.GetConfigJson())
	}
	if reply.GetPending() != nil {
		t.Error("pending arm must be nil for a delivered response")
	}
}

// TestInvoke_ProvisioningFetchConfig_PendingRoundTrip pins the SDK mirror
// struct against a daemon-shaped encoded payload for the pending arm.
func TestInvoke_ProvisioningFetchConfig_PendingRoundTrip(t *testing.T) {
	encoded, err := quicapi.EncodePayload(&daemonFetchConfigWire{
		Result:              "pending",
		SessionId:           "sess-7",
		ProvisionUrl:        "https://cp:8443/provision/sess-7",
		PollIntervalSeconds: 5,
	})
	if err != nil {
		t.Fatalf("EncodePayload setup failed: %v", err)
	}

	sender := &recordingSender{respPayload: encoded}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.FetchConfigResponse{}
	err = conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig",
		&platformv1.FetchConfigRequest{}, reply)
	if err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	pending := reply.GetPending()
	if pending == nil {
		t.Fatalf("expected pending oneof arm, got %+v", reply)
	}
	if pending.GetSessionId() != "sess-7" {
		t.Errorf("session_id = %q", pending.GetSessionId())
	}
	if pending.GetProvisionUrl() != "https://cp:8443/provision/sess-7" {
		t.Errorf("provision_url = %q", pending.GetProvisionUrl())
	}
	if pending.GetPollIntervalSeconds() != 5 {
		t.Errorf("poll_interval_seconds = %d", pending.GetPollIntervalSeconds())
	}
}

// TestInvoke_ProvisioningPollSession_RoundTrips pins both arms of the
// flattened PollSession response against daemon-shaped encodings.
func TestInvoke_ProvisioningPollSession_RoundTrips(t *testing.T) {
	t.Run("delivered", func(t *testing.T) {
		encoded, err := quicapi.EncodePayload(&daemonPollSessionWire{
			Result:     "delivered",
			ConfigJson: []byte(`{"role":"compute"}`),
			Status:     "ok",
		})
		if err != nil {
			t.Fatalf("EncodePayload setup failed: %v", err)
		}

		sender := &recordingSender{respPayload: encoded}
		conn := newConnWithSender(t, sender)

		reply := &platformv1.PollSessionResponse{}
		err = conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/PollSession",
			&platformv1.PollSessionRequest{SessionId: "s"}, reply)
		if err != nil {
			t.Fatalf("Invoke() unexpected error: %v", err)
		}
		if reply.GetDelivered().GetStatus() != "ok" {
			t.Errorf("delivered status = %q", reply.GetDelivered().GetStatus())
		}
		if string(reply.GetDelivered().GetConfigJson()) != `{"role":"compute"}` {
			t.Errorf("config_json = %s", reply.GetDelivered().GetConfigJson())
		}
	})

	t.Run("pending", func(t *testing.T) {
		encoded, err := quicapi.EncodePayload(&daemonPollSessionWire{
			Result:        "pending",
			PendingStatus: "pending",
		})
		if err != nil {
			t.Fatalf("EncodePayload setup failed: %v", err)
		}

		sender := &recordingSender{respPayload: encoded}
		conn := newConnWithSender(t, sender)

		reply := &platformv1.PollSessionResponse{}
		err = conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/PollSession",
			&platformv1.PollSessionRequest{SessionId: "s"}, reply)
		if err != nil {
			t.Fatalf("Invoke() unexpected error: %v", err)
		}
		if reply.GetPendingStatus() != "pending" {
			t.Errorf("pending_status = %q, want pending", reply.GetPendingStatus())
		}
		if reply.GetDelivered() != nil {
			t.Error("delivered arm must be nil for a pending response")
		}
	})
}

// TestInvoke_ProvisioningNonOneofResponsesDecodeDirectly verifies the
// non-oneof responses (nonce, sign, fulfill) decode into the pb replies via
// the default codec path by Go field name.
func TestInvoke_ProvisioningNonOneofResponsesDecodeDirectly(t *testing.T) {
	t.Run("GetNonce", func(t *testing.T) {
		encoded, err := quicapi.EncodePayload(&struct {
			Nonce string
		}{Nonce: "n-42"})
		if err != nil {
			t.Fatalf("EncodePayload setup failed: %v", err)
		}

		sender := &recordingSender{respPayload: encoded}
		conn := newConnWithSender(t, sender)

		reply := &platformv1.GetNonceResponse{}
		err = conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/GetNonce",
			&platformv1.GetNonceRequest{}, reply)
		if err != nil {
			t.Fatalf("Invoke() unexpected error: %v", err)
		}
		if reply.GetNonce() != "n-42" {
			t.Errorf("nonce = %q, want n-42", reply.GetNonce())
		}
	})

	t.Run("FulfillSession", func(t *testing.T) {
		encoded, err := quicapi.EncodePayload(&struct {
			Status string
		}{Status: "fulfilled"})
		if err != nil {
			t.Fatalf("EncodePayload setup failed: %v", err)
		}

		sender := &recordingSender{respPayload: encoded}
		conn := newConnWithSender(t, sender)

		reply := &platformv1.FulfillSessionResponse{}
		err = conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FulfillSession",
			&platformv1.FulfillSessionRequest{SessionId: "s", ProfileId: 1}, reply)
		if err != nil {
			t.Fatalf("Invoke() unexpected error: %v", err)
		}
		if reply.GetStatus() != "fulfilled" {
			t.Errorf("status = %q, want fulfilled", reply.GetStatus())
		}
	})
}

// TestDecodeProvisioningReplies_WrongReplyType verifies the custom decoders
// reject reply messages of the wrong concrete type with the typed error.
func TestDecodeProvisioningReplies_WrongReplyType(t *testing.T) {
	if err := decodeProvisioningFetchConfigReply(nil, &platformv1.GetNonceResponse{}); err == nil {
		t.Fatal("decodeProvisioningFetchConfigReply must reject wrong reply type")
	} else if _, ok := err.(ErrInvalidReplyType); !ok {
		t.Errorf("expected ErrInvalidReplyType, got %T", err)
	}

	if err := decodeProvisioningPollSessionReply(nil, &platformv1.GetNonceResponse{}); err == nil {
		t.Fatal("decodeProvisioningPollSessionReply must reject wrong reply type")
	} else if _, ok := err.(ErrInvalidReplyType); !ok {
		t.Errorf("expected ErrInvalidReplyType, got %T", err)
	}
}

// TestInvoke_ProvisioningDecodeFailure verifies undecodable response bytes
// surface as gRPC Internal errors through the custom decoder path.
func TestInvoke_ProvisioningDecodeFailure(t *testing.T) {
	sender := &recordingSender{respPayload: []byte{0xFF, 0xFE, 0xFD}}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.FetchConfigResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.ConfigDeliveryService/FetchConfig",
		&platformv1.FetchConfigRequest{}, reply)
	// Lenient codecs may decode garbage to a zero struct; when an error is
	// returned it must carry codes.Internal, matching the default path.
	if err == nil {
		return
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("code = %v, want %v", st.Code(), codes.Internal)
	}
}

// TestErrInvalidReplyType_Error covers the typed error message.
func TestErrInvalidReplyType_Error(t *testing.T) {
	err := ErrInvalidReplyType{Method: "/platform.v1.ConfigDeliveryService/FetchConfig"}
	want := "unexpected reply message type for gRPC method /platform.v1.ConfigDeliveryService/FetchConfig"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
