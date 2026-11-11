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

package orchestrator

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/pkg/orchestration"
)

// TestClassify_NativeOrchestrationErrors covers the errors the embedded
// transport returns unchanged: they are native orchestration errors, not
// QBErrors, so the SDK predicates miss them.
func TestClassify_NativeOrchestrationErrors(t *testing.T) {
	cases := map[string]struct {
		err  error
		want ErrorKind
	}{
		"session not found":    {&orchestration.SessionNotFoundError{}, KindNotFound},
		"agent not found":      {&orchestration.AgentNotFoundError{}, KindNotFound},
		"job not found":        {&orchestration.JobNotFoundError{}, KindNotFound},
		"invalid filter param": {&orchestration.InvalidFilterParamError{}, KindInvalidArgument},
		"wrapped session":      {&OperationError{Op: "CloseSession", Err: fmt.Errorf("embedded: %w", &orchestration.SessionNotFoundError{})}, KindNotFound},
		"session sentinel":     {orchestration.ErrSessionNotFound, KindNotFound},
		"job sentinel":         {orchestration.ErrJobNotFound, KindNotFound},
		"filter sentinel":      {orchestration.ErrFilterParamInvalid, KindInvalidArgument},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Fatalf("Classify(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
