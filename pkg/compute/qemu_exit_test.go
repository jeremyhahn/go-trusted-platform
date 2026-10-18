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

package compute

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The exit of a VM that Stop is stopping is the one exit the lifecycle
// records as Stopped.
func TestRecordExit_RequestedStopIsStopped(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir()})
	require.NoError(t, orch.lifecycle.SetState("vm1", StateStopping))
	qi.instance.State = StateStopping

	orch.recordExit("vm1", qi)

	assertVMState(t, orch, qi, StateStopped)
	assert.Zero(t, qi.instance.PID)
}

// The lifecycle has no transition from these states for an exit nobody
// asked for, so the state is kept; the process is still marked gone.
func TestRecordExit_OtherStatesAreKept(t *testing.T) {
	tests := []struct {
		name  string
		state InstanceState
	}{
		{"running", StateRunning},
		{"suspended", StateSuspended},
		{"error", StateError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir()})
			if tt.state != StateRunning {
				require.NoError(t, orch.lifecycle.SetState("vm1", tt.state))
				qi.instance.State = tt.state
			}

			orch.recordExit("vm1", qi)

			assertVMState(t, orch, qi, tt.state)
			assert.Zero(t, qi.instance.PID)
		})
	}
}

// An instance deleted or migrated away before its process exits is not
// brought back into the lifecycle.
func TestRecordExit_DeletedInstanceIsNotRecreated(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir()})
	require.NoError(t, orch.lifecycle.DeleteInstance("vm1"))

	orch.recordExit("vm1", qi)

	_, err := orch.GetState(context.Background(), "vm1")
	assert.True(t, errors.Is(err, ErrInstanceNotFound), "GetState err = %v, want ErrInstanceNotFound", err)
	assert.Equal(t, StateRunning, qi.instance.State)
	assert.Zero(t, qi.instance.PID)
}
