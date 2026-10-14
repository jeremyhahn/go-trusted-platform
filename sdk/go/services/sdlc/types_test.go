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

package sdlc

import (
	"reflect"
	"testing"

	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/sdlc"
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
		{"ProjectBinding", reflect.TypeFor[ProjectBinding](), reflect.TypeFor[upstream.ProjectBinding]()},
		{"ForgeConfig", reflect.TypeFor[ForgeConfig](), reflect.TypeFor[upstream.ForgeConfig]()},
		{"ReviewerConfig", reflect.TypeFor[ReviewerConfig](), reflect.TypeFor[upstream.ReviewerConfig]()},
		{"ReviewPolicy", reflect.TypeFor[ReviewPolicy](), reflect.TypeFor[upstream.ReviewPolicy]()},
		{"RankingPolicy", reflect.TypeFor[RankingPolicy](), reflect.TypeFor[upstream.RankingPolicy]()},
		{"OnboardingConfig", reflect.TypeFor[OnboardingConfig](), reflect.TypeFor[upstream.OnboardingConfig]()},
		{"Delivery", reflect.TypeFor[Delivery](), reflect.TypeFor[upstream.Delivery]()},
		{"PullRequest", reflect.TypeFor[PullRequest](), reflect.TypeFor[upstream.PullRequest]()},
		{"CheckRecord", reflect.TypeFor[CheckRecord](), reflect.TypeFor[upstream.CheckRecord]()},
		{"ReviewRecord", reflect.TypeFor[ReviewRecord](), reflect.TypeFor[upstream.ReviewRecord]()},
		{"SupersessionRecord", reflect.TypeFor[SupersessionRecord](), reflect.TypeFor[upstream.SupersessionRecord]()},
		{"OnboardingReport", reflect.TypeFor[OnboardingReport](), reflect.TypeFor[upstream.OnboardingReport]()},
		{"ConformanceReport", reflect.TypeFor[ConformanceReport](), reflect.TypeFor[upstream.ConformanceReport]()},
		{"ConformanceCheckResult", reflect.TypeFor[ConformanceCheckResult](), reflect.TypeFor[upstream.ConformanceCheckResult]()},
		{"ConformanceFinding", reflect.TypeFor[ConformanceFinding](), reflect.TypeFor[upstream.ConformanceFinding]()},
		{"BindRequest", reflect.TypeFor[BindRequest](), reflect.TypeFor[upstream.BindRequest]()},
		{"UnbindRequest", reflect.TypeFor[UnbindRequest](), reflect.TypeFor[upstream.UnbindRequest]()},
		{"UnbindResponse", reflect.TypeFor[UnbindResponse](), reflect.TypeFor[upstream.UnbindResponse]()},
		{"GetBindingRequest", reflect.TypeFor[GetBindingRequest](), reflect.TypeFor[upstream.GetBindingRequest]()},
		{"GetDeliveryRequest", reflect.TypeFor[GetDeliveryRequest](), reflect.TypeFor[upstream.GetDeliveryRequest]()},
		{"ListForgesRequest", reflect.TypeFor[ListForgesRequest](), reflect.TypeFor[upstream.ListForgesRequest]()},
		{"ListForgesResponse", reflect.TypeFor[ListForgesResponse](), reflect.TypeFor[upstream.ListForgesResponse]()},
		{"OnboardRequest", reflect.TypeFor[OnboardRequest](), reflect.TypeFor[upstream.OnboardRequest]()},
		{"ConformanceRequest", reflect.TypeFor[ConformanceRequest](), reflect.TypeFor[upstream.ConformanceRequest]()},
	}
	for _, tc := range cases {
		if tc.got != tc.upstream {
			t.Errorf("%s = %v, want the upstream type %v", tc.name, tc.got, tc.upstream)
		}
	}
}
