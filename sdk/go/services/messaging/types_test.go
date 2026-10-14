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

package messaging

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/messaging"
)

// deltaEntity is the entity the delta helper tests patch.
type deltaEntity struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TestTypes_AreUpstreamAliases proves every re-exported type IS the upstream
// type, so a value crosses the boundary without conversion. A defined type
// in place of an alias would be a distinct reflect.Type.
func TestTypes_AreUpstreamAliases(t *testing.T) {
	cases := []struct {
		name     string
		got      reflect.Type
		upstream reflect.Type
	}{
		{"Client", reflect.TypeFor[Client](), reflect.TypeFor[upstream.Client]()},
		{"Channel", reflect.TypeFor[Channel](), reflect.TypeFor[upstream.Channel]()},
		{"Subscription", reflect.TypeFor[Subscription](), reflect.TypeFor[upstream.Subscription]()},
		{"SubscriptionFilter", reflect.TypeFor[SubscriptionFilter](), reflect.TypeFor[upstream.SubscriptionFilter]()},
		{"Message", reflect.TypeFor[Message](), reflect.TypeFor[upstream.Message]()},
		{"MessageType", reflect.TypeFor[MessageType](), reflect.TypeFor[upstream.MessageType]()},
		{"EventType", reflect.TypeFor[EventType](), reflect.TypeFor[upstream.EventType]()},
		{"Stats", reflect.TypeFor[Stats](), reflect.TypeFor[upstream.Stats]()},
		{"ChannelStats", reflect.TypeFor[ChannelStats](), reflect.TypeFor[upstream.ChannelStats]()},
		{"DedupStats", reflect.TypeFor[DedupStats](), reflect.TypeFor[upstream.DedupStats]()},
		{"DedupInfo", reflect.TypeFor[DedupInfo](), reflect.TypeFor[upstream.DedupInfo]()},
		{"DeltaPayload", reflect.TypeFor[DeltaPayload](), reflect.TypeFor[upstream.DeltaPayload]()},
		{"FieldChange", reflect.TypeFor[FieldChange](), reflect.TypeFor[upstream.FieldChange]()},
		{"OpType", reflect.TypeFor[OpType](), reflect.TypeFor[upstream.OpType]()},
		{"DeltaBuilder", reflect.TypeFor[DeltaBuilder](), reflect.TypeFor[upstream.DeltaBuilder]()},
		{"DeltaApplier", reflect.TypeFor[DeltaApplier[deltaEntity]](), reflect.TypeFor[upstream.DeltaApplier[deltaEntity]]()},
		{"CreateChannelRequest", reflect.TypeFor[CreateChannelRequest](), reflect.TypeFor[upstream.CreateChannelRequest]()},
		{"DeleteChannelRequest", reflect.TypeFor[DeleteChannelRequest](), reflect.TypeFor[upstream.DeleteChannelRequest]()},
		{"GetChannelRequest", reflect.TypeFor[GetChannelRequest](), reflect.TypeFor[upstream.GetChannelRequest]()},
		{"ListChannelsRequest", reflect.TypeFor[ListChannelsRequest](), reflect.TypeFor[upstream.ListChannelsRequest]()},
		{"ListChannelsResponse", reflect.TypeFor[ListChannelsResponse](), reflect.TypeFor[upstream.ListChannelsResponse]()},
		{"SubscribeRequest", reflect.TypeFor[SubscribeRequest](), reflect.TypeFor[upstream.SubscribeRequest]()},
		{"UnsubscribeRequest", reflect.TypeFor[UnsubscribeRequest](), reflect.TypeFor[upstream.UnsubscribeRequest]()},
		{"PublishRequest", reflect.TypeFor[PublishRequest](), reflect.TypeFor[upstream.PublishRequest]()},
		{"PublishDeltaRequest", reflect.TypeFor[PublishDeltaRequest](), reflect.TypeFor[upstream.PublishDeltaRequest]()},
		{"WatchChannelRequest", reflect.TypeFor[WatchChannelRequest](), reflect.TypeFor[upstream.WatchChannelRequest]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported constant carries the
// upstream value and type, so a channel, message or delta built through this
// package means what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"CodecJSON", CodecJSON, upstream.CodecJSON},
		{"CodecMsgpack", CodecMsgpack, upstream.CodecMsgpack},
		{"CodecProtobuf", CodecProtobuf, upstream.CodecProtobuf},
		{"MessageTypeSubscribe", MessageTypeSubscribe, upstream.MessageTypeSubscribe},
		{"MessageTypeUnsubscribe", MessageTypeUnsubscribe, upstream.MessageTypeUnsubscribe},
		{"MessageTypePublish", MessageTypePublish, upstream.MessageTypePublish},
		{"MessageTypeNotification", MessageTypeNotification, upstream.MessageTypeNotification},
		{"MessageTypePing", MessageTypePing, upstream.MessageTypePing},
		{"MessageTypePong", MessageTypePong, upstream.MessageTypePong},
		{"MessageTypeAck", MessageTypeAck, upstream.MessageTypeAck},
		{"MessageTypeError", MessageTypeError, upstream.MessageTypeError},
		{"MessageTypeData", MessageTypeData, upstream.MessageTypeData},
		{"MessageTypeControl", MessageTypeControl, upstream.MessageTypeControl},
		{"MessageTypeHeartbeat", MessageTypeHeartbeat, upstream.MessageTypeHeartbeat},
		{"EventTypePut", EventTypePut, upstream.EventTypePut},
		{"EventTypeDelete", EventTypeDelete, upstream.EventTypeDelete},
		{"OpSet", OpSet, upstream.OpSet},
		{"OpDelete", OpDelete, upstream.OpDelete},
		{"OpAppend", OpAppend, upstream.OpAppend},
		{"OpIncrement", OpIncrement, upstream.OpIncrement},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestDeltaHelpers_ApplyBuiltDelta proves the re-exported constructors return
// working upstream helpers: a delta built here patches an entity applied here.
func TestDeltaHelpers_ApplyBuiltDelta(t *testing.T) {
	delta := NewDeltaBuilder().
		WithEntityID("entity-1").
		Set("name", "after").
		Increment("count", 2).
		Build()

	got, err := NewDeltaApplier[deltaEntity]().Apply(deltaEntity{Name: "before", Count: 1}, delta)
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	want := deltaEntity{Name: "after", Count: 3}
	if got != want {
		t.Errorf("Apply() = %+v, want %+v", got, want)
	}
	if delta.EntityID != "entity-1" {
		t.Errorf("Build().EntityID = %q, want %q", delta.EntityID, "entity-1")
	}
}

// TestDeltaBuilder_EmptyPathRejected proves a malformed change built here is
// rejected when applied, not silently dropped.
func TestDeltaBuilder_EmptyPathRejected(t *testing.T) {
	delta := NewDeltaBuilder().Set("", "value").Build()

	if _, err := NewDeltaApplier[deltaEntity]().Apply(deltaEntity{}, delta); err == nil {
		t.Fatal("Apply() of an empty-path change error = nil, want an error")
	}
}

// TestDeltaApplier_UnencodableEntity proves the applier reports an entity it
// cannot represent instead of returning it unpatched.
func TestDeltaApplier_UnencodableEntity(t *testing.T) {
	delta := NewDeltaBuilder().Set("name", "after").Build()

	if _, err := NewDeltaApplier[chan int]().Apply(make(chan int), delta); err == nil {
		t.Fatal("Apply() to a channel entity error = nil, want an error")
	}
}
