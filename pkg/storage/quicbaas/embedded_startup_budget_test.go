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

package quicbaas

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestStartupTimeout_IsNotDerivedFromRequestTimeout is the regression guard
// for #270's category error: startup used to be budgeted at
// RequestTimeout*3, so tuning how long ONE DAO operation may take silently
// retuned how long first boot was allowed to take, in a ratio nobody chose.
//
// Startup constructs the barrier, opens the TPM, creates the system tenant
// and seeds five roles. None of that has any relationship to a request.
func TestStartupTimeout_IsNotDerivedFromRequestTimeout(t *testing.T) {
	c := &Config{DataDir: t.TempDir(), SPIFFETrustDomain: "example.internal"}
	c.SetDefaults()

	base := c.StartupTimeout
	require.Equal(t, DefaultStartupTimeout, base)

	// Moving the request timeout must not move the startup budget.
	c.RequestTimeout = time.Second
	c.SetDefaults()
	assert.Equal(t, base, c.StartupTimeout,
		"startup budget must not track RequestTimeout")

	c.RequestTimeout = time.Hour
	c.SetDefaults()
	assert.Equal(t, base, c.StartupTimeout,
		"startup budget must not track RequestTimeout")
}

// TestStartupTimeout_ExplicitValueSurvivesDefaults proves an operator's
// configured budget is not overwritten by SetDefaults.
func TestStartupTimeout_ExplicitValueSurvivesDefaults(t *testing.T) {
	c := &Config{
		DataDir:           t.TempDir(),
		SPIFFETrustDomain: "example.internal",
		StartupTimeout:    45 * time.Second,
	}
	c.SetDefaults()
	assert.Equal(t, 45*time.Second, c.StartupTimeout)
}

// TestWaitForReady_ContextEndedIsNotABudgetFailure is the fix for the
// misdiagnosis in #270.
//
// The reported failure was a caller context expiring, but waitForReady
// returned the same ErrTimeout{Operation: "start"} it returns for a blown
// budget, so the report named the wrong cause and the budget it blamed
// still had 56 seconds left. The two must be distinguishable.
func TestWaitForReady_ContextEndedIsNotABudgetFailure(t *testing.T) {
	cfg := TestConfig(t)
	cfg.SetDefaults()
	srv, err := NewEmbeddedServer(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = srv.waitForReadyWith(ctx, neverStarted{})
	require.Error(t, err)

	var canceled ErrStartupCanceled
	require.ErrorAs(t, err, &canceled, "an ended caller context must report as ErrStartupCanceled")
	assert.ErrorIs(t, err, context.Canceled, "the context's own cause must survive unwrapping")

	var budget ErrStartupTimeout
	assert.False(t, errors.As(err, &budget),
		"a caller's context ending must NOT be reported as a blown startup budget")
}

// TestWaitForReady_BudgetExpiryNamesTheBudget covers the other arm: when
// the budget really is what expired, the error says so and names it, so the
// reader is sent to the startup budget rather than to the server.
func TestWaitForReady_BudgetExpiryNamesTheBudget(t *testing.T) {
	cfg := TestConfig(t)
	cfg.StartupTimeout = 20 * time.Millisecond
	srv, err := NewEmbeddedServer(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	err = srv.waitForReadyWith(context.Background(), neverStarted{})
	require.Error(t, err)

	var budget ErrStartupTimeout
	require.ErrorAs(t, err, &budget)
	assert.Equal(t, 20*time.Millisecond, budget.Budget,
		"the error must name the budget that expired")

	var canceled ErrStartupCanceled
	assert.False(t, errors.As(err, &canceled),
		"a blown budget must NOT be reported as a caller cancellation")
}

// TestWaitForReady_AlreadyStartedReturnsWithoutTicking proves the initial
// check happens before the ticker.
//
// This is not micro-optimisation. The embedded server's Start calls
// initialize synchronously and initialize sets the started flag as its FIRST
// action, so the flag is always already true when waitForReady runs.
// Polling first therefore charged every single startup a pointless 100ms
// for a value that could never change during the wait.
func TestWaitForReady_AlreadyStartedReturnsWithoutTicking(t *testing.T) {
	cfg := TestConfig(t)
	cfg.SetDefaults()
	srv, err := NewEmbeddedServer(cfg, logging.DefaultLogger())
	require.NoError(t, err)

	begin := time.Now()
	require.NoError(t, srv.waitForReadyWith(context.Background(), alreadyStarted{}))
	elapsed := time.Since(begin)

	assert.Less(t, elapsed, startupPollInterval,
		"an already-started server must return before the first tick, not after it")
}

// startedReporter is the narrow thing waitForReady actually needs: whether
// the server reports itself started.
type alreadyStarted struct{}

func (alreadyStarted) IsStarted() bool { return true }

type neverStarted struct{}

func (neverStarted) IsStarted() bool { return false }
