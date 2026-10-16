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

package kv

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kv"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
)

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
		{"PutRequest", reflect.TypeFor[PutRequest](), reflect.TypeFor[service.PutRequest]()},
		{"PutResponse", reflect.TypeFor[PutResponse](), reflect.TypeFor[service.PutResponse]()},
		{"GetRequest", reflect.TypeFor[GetRequest](), reflect.TypeFor[service.GetRequest]()},
		{"GetResponse", reflect.TypeFor[GetResponse](), reflect.TypeFor[service.GetResponse]()},
		{"DeleteRequest", reflect.TypeFor[DeleteRequest](), reflect.TypeFor[service.DeleteRequest]()},
		{"DeleteResponse", reflect.TypeFor[DeleteResponse](), reflect.TypeFor[service.DeleteResponse]()},
		{"ListRequest", reflect.TypeFor[ListRequest](), reflect.TypeFor[service.ListRequest]()},
		{"ListResponse", reflect.TypeFor[ListResponse](), reflect.TypeFor[service.ListResponse]()},
		{"Entity", reflect.TypeFor[Entity](), reflect.TypeFor[service.Entity]()},
		{"ConsistencyLevel", reflect.TypeFor[ConsistencyLevel](), reflect.TypeFor[service.ConsistencyLevel]()},
		{"WriteMode", reflect.TypeFor[WriteMode](), reflect.TypeFor[service.WriteMode]()},
		{"Watcher", reflect.TypeFor[Watcher](), reflect.TypeFor[upstream.Watcher]()},
		{"WatchEvent", reflect.TypeFor[WatchEvent](), reflect.TypeFor[upstream.WatchEvent]()},
		{"EventType", reflect.TypeFor[EventType](), reflect.TypeFor[upstream.EventType]()},
		{"WatchOption", reflect.TypeFor[WatchOption](), reflect.TypeFor[upstream.WatchOption]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestConstants_MatchUpstream proves each re-exported consistency level,
// write mode and event type carries the upstream value and type, so a request
// built through this package means what the server reads.
func TestConstants_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      any
		upstream any
	}{
		{"ConsistencyLevelUnspecified", ConsistencyLevelUnspecified, service.ConsistencyLevelUnspecified},
		{"ConsistencyLevelEventual", ConsistencyLevelEventual, service.ConsistencyLevelEventual},
		{"ConsistencyLevelLinearizable", ConsistencyLevelLinearizable, service.ConsistencyLevelLinearizable},
		{"ConsistencyLevelStrong", ConsistencyLevelStrong, service.ConsistencyLevelStrong},
		{"WriteModeSync", WriteModeSync, service.WriteModeSync},
		{"WriteModeWALDurable", WriteModeWALDurable, service.WriteModeWALDurable},
		{"WriteModeBatched", WriteModeBatched, service.WriteModeBatched},
		{"EventPut", EventPut, upstream.EventPut},
		{"EventDelete", EventDelete, upstream.EventDelete},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %#v, want %#v", tc.name, tc.got, tc.upstream)
		}
	}
}

// TestWatchOptions_MatchUpstream proves each forwarded watch option sets the
// same watch state as its upstream counterpart, and that the state is not
// the zero value, so a forwarder wired to the wrong option or to nothing fails.
func TestWatchOptions_MatchUpstream(t *testing.T) {
	cases := []struct {
		name     string
		got      WatchOption
		upstream upstream.WatchOption
	}{
		{"WithStartRevision", WithStartRevision(42), upstream.WithStartRevision(42)},
		{"WithPrevKV", WithPrevKV(), upstream.WithPrevKV()},
		{"WithProgressNotify", WithProgressNotify(), upstream.WithProgressNotify()},
		{"WithFilterPut", WithFilterPut(), upstream.WithFilterPut()},
		{"WithFilterDelete", WithFilterDelete(), upstream.WithFilterDelete()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appliedState(tc.got)
			want := appliedState(tc.upstream)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s state = %+v, want the upstream state %+v", tc.name, got, want)
			}
			if reflect.ValueOf(got).IsZero() {
				t.Errorf("%s left the watch state zero", tc.name)
			}
		})
	}
}

// TestWithStartRevision_ForwardsTheRevision proves the revision argument
// reaches the upstream option: two revisions give two states, and revision 0
// (watch from now) gives the upstream revision-0 state rather than a default.
func TestWithStartRevision_ForwardsTheRevision(t *testing.T) {
	if reflect.DeepEqual(appliedState(WithStartRevision(7)), appliedState(WithStartRevision(8))) {
		t.Error("WithStartRevision(7) and WithStartRevision(8) set the same state")
	}
	got := appliedState(WithStartRevision(0))
	want := appliedState(upstream.WithStartRevision(0))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WithStartRevision(0) state = %+v, want the upstream state %+v", got, want)
	}
}

// appliedState applies opt to a fresh upstream watch-options value and returns
// that value. The options struct is unexported upstream, so it is built from
// the option's own parameter type.
func appliedState(opt WatchOption) any {
	fn := reflect.ValueOf(opt)
	state := reflect.New(fn.Type().In(0).Elem())
	fn.Call([]reflect.Value{state})
	return state.Elem().Interface()
}
