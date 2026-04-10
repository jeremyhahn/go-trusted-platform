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

package metrics

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrCollectorAlreadyRegistered(t *testing.T) {
	err := ErrCollectorAlreadyRegistered{Name: "test_collector"}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "test_collector")
	assert.Contains(t, err.Error(), "already registered")
}

func TestErrInvalidConfiguration_WithError(t *testing.T) {
	innerErr := errors.New("invalid value")
	err := ErrInvalidConfiguration{
		Field: "Port",
		Err:   innerErr,
	}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Port")
	assert.Contains(t, err.Error(), "invalid value")
	assert.Contains(t, err.Error(), "invalid metrics configuration")
}

func TestErrInvalidConfiguration_WithoutError(t *testing.T) {
	err := ErrInvalidConfiguration{
		Field: "Namespace",
	}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Namespace")
	assert.Contains(t, err.Error(), "invalid metrics configuration")
	assert.NotContains(t, err.Error(), "<nil>")
}

func TestErrMetricsNotEnabled(t *testing.T) {
	err := ErrMetricsNotEnabled{}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled")
}

func TestErrCollectorRegistration(t *testing.T) {
	innerErr := errors.New("prometheus: duplicate metrics collector registration attempted")
	err := ErrCollectorRegistration{
		Name: "runtime_collector",
		Err:  innerErr,
	}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "runtime_collector")
	assert.Contains(t, err.Error(), "failed to register collector")
	assert.Contains(t, err.Error(), "duplicate metrics")
}

func TestErrInvalidMetricName(t *testing.T) {
	err := ErrInvalidMetricName{Name: "invalid-name-with-dashes"}

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid-name-with-dashes")
	assert.Contains(t, err.Error(), "invalid metric name")
}

func TestErrorsAsInterface(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "ErrCollectorAlreadyRegistered",
			err:  ErrCollectorAlreadyRegistered{Name: "test"},
		},
		{
			name: "ErrInvalidConfiguration",
			err:  ErrInvalidConfiguration{Field: "test"},
		},
		{
			name: "ErrMetricsNotEnabled",
			err:  ErrMetricsNotEnabled{},
		},
		{
			name: "ErrCollectorRegistration",
			err:  ErrCollectorRegistration{Name: "test", Err: errors.New("test")},
		},
		{
			name: "ErrInvalidMetricName",
			err:  ErrInvalidMetricName{Name: "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := tt.err
			assert.NotNil(t, e)
			assert.NotEmpty(t, e.Error())
		})
	}
}
