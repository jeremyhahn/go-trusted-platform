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

package dns

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDatastore(t *testing.T) {
	logger := logging.DefaultLogger()

	// Create mock storage for testing
	mockStorage := quicbaas.NewMockStorage()

	ds := NewDatastore(mockStorage, logger)

	assert.NotNil(t, ds)
	assert.Equal(t, mockStorage, ds.storage)
	assert.Equal(t, logger, ds.logger)
}

func TestDatastore_ZoneDAO(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()

	ds := NewDatastore(mockStorage, logger)

	dao, err := ds.ZoneDAO()
	require.NoError(t, err)
	assert.NotNil(t, dao)
}
