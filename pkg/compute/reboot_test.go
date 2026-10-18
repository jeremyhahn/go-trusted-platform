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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStartStopper records the order of Stop and Start calls.
type fakeStartStopper struct {
	calls    []string
	stopErr  error
	startErr error
}

func (f *fakeStartStopper) Start(ctx context.Context, instanceID string) error {
	f.calls = append(f.calls, "start "+instanceID)
	return f.startErr
}

func (f *fakeStartStopper) Stop(ctx context.Context, instanceID string) error {
	f.calls = append(f.calls, "stop "+instanceID)
	return f.stopErr
}

func TestReboot_StopsThenStarts(t *testing.T) {
	o := &fakeStartStopper{}

	require.NoError(t, Reboot(context.Background(), o, "vm1"))
	assert.Equal(t, []string{"stop vm1", "start vm1"}, o.calls)
}

func TestReboot_StopFailureSkipsStart(t *testing.T) {
	o := &fakeStartStopper{stopErr: ErrInstanceNotRunning}

	err := Reboot(context.Background(), o, "vm1")
	require.ErrorIs(t, err, ErrInstanceNotRunning)
	assert.Equal(t, []string{"stop vm1"}, o.calls)
}

func TestReboot_StartFailureKeepsSentinel(t *testing.T) {
	o := &fakeStartStopper{startErr: ErrInstanceNotFound}

	err := Reboot(context.Background(), o, "vm1")
	require.ErrorIs(t, err, ErrInstanceNotFound)
	assert.Equal(t, []string{"stop vm1", "start vm1"}, o.calls)
}
