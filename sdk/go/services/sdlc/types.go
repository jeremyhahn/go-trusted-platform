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
	upstream "github.com/jeremyhahn/go-quicbaas/sdk/go/client/sdlc"
)

// Client is the SDLC module client returned by quicbaas.Client.SDLC().
type Client = upstream.Client

// Forge bindings: which forge a project delivers to, and how.
type (
	// ProjectBinding attaches a forge repository and its delivery policy to
	// an orchestration project.
	ProjectBinding = upstream.ProjectBinding
	// ForgeConfig names the repository a project delivers to.
	ForgeConfig = upstream.ForgeConfig
	// ReviewerConfig configures the project's reviewer. A bind replaces the
	// whole binding, so a bind that omits it erases the reviewer.
	ReviewerConfig = upstream.ReviewerConfig
	// ReviewPolicy decides when a pull request may land.
	ReviewPolicy = upstream.ReviewPolicy
	// RankingPolicy is a project's contribution to task ordering.
	RankingPolicy = upstream.RankingPolicy
	// OnboardingConfig declares what Onboard writes to the forge and what
	// Conformance checks.
	OnboardingConfig = upstream.OnboardingConfig
)

// Deliveries: what a task's attempt published.
type (
	// Delivery is what one task attempt published.
	Delivery = upstream.Delivery
	// PullRequest is the pull request an attempt opened.
	PullRequest = upstream.PullRequest
	// CheckRecord is the latest state of one check context on one head.
	CheckRecord = upstream.CheckRecord
	// ReviewRecord is one reviewer's verdict on one head.
	ReviewRecord = upstream.ReviewRecord
	// SupersessionRecord tells a live CI run from one a newer head made
	// obsolete.
	SupersessionRecord = upstream.SupersessionRecord
)

// Onboarding and conformance reports.
type (
	OnboardingReport       = upstream.OnboardingReport
	ConformanceReport      = upstream.ConformanceReport
	ConformanceCheckResult = upstream.ConformanceCheckResult
	ConformanceFinding     = upstream.ConformanceFinding
)

// Requests and responses of the Client verbs.
type (
	BindRequest        = upstream.BindRequest
	UnbindRequest      = upstream.UnbindRequest
	UnbindResponse     = upstream.UnbindResponse
	GetBindingRequest  = upstream.GetBindingRequest
	GetDeliveryRequest = upstream.GetDeliveryRequest
	ListForgesRequest  = upstream.ListForgesRequest
	ListForgesResponse = upstream.ListForgesResponse
	OnboardRequest     = upstream.OnboardRequest
	ConformanceRequest = upstream.ConformanceRequest
)
