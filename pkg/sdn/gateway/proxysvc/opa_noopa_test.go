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

// A build without the opa tag refuses an enabled OPA evaluator with the
// engine's ErrOPANotBuilt, and still reports a disabled one as disabled
// (#1691). make test-noopa runs these.

//go:build !opa

package proxysvc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

func TestNewOPAEvaluator_NoOPA_AnEnabledEvaluatorIsNotBuilt(t *testing.T) {
	ev, err := NewOPAEvaluator(context.Background(), &OPAConfig{Enabled: true, PolicyDir: t.TempDir()})
	assert.Nil(t, ev)
	var notBuilt opa.ErrOPANotBuilt
	require.True(t, errors.As(err, &notBuilt), "got %v", err)
}

func TestNewOPAEvaluator_NoOPA_ADisabledEvaluatorIsDisabled(t *testing.T) {
	_, err := NewOPAEvaluator(context.Background(), &OPAConfig{})
	var disabled *ErrOPADisabled
	require.True(t, errors.As(err, &disabled), "got %v", err)
}
