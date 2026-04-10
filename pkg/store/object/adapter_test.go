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

package object

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
)

// TestXKMSObjectAdapter_Read tests the Read method with success and error cases
func TestXKMSObjectAdapter_Read(t *testing.T) {
	logger := logging.DefaultLogger()
	storage := NewMemoryClient()

	store, err := NewObjectStore(logger, storage, "tmp/testdata", nil)
	assert.Nil(t, err)

	adapter := NewXKMSObjectAdapter(store)

	// Test success case
	testData := []byte("test data for adapter")
	err = store.Save([]byte("adapter_test/read_test.txt"), testData)
	assert.Nil(t, err)

	data, err := adapter.Read("adapter_test/read_test.txt")
	assert.Nil(t, err)
	assert.Equal(t, testData, data)

	// Cleanup
	store.Delete([]byte("adapter_test/read_test.txt"))

	// Test error case - not found
	_, err = adapter.Read("adapter_test/nonexistent.txt")
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))
}

// TestXKMSObjectAdapter_Write tests the Write method with success and error cases
func TestXKMSObjectAdapter_Write(t *testing.T) {
	logger := logging.DefaultLogger()
	storage := NewMemoryClient()

	store, err := NewObjectStore(logger, storage, "tmp/testdata", nil)
	assert.Nil(t, err)

	adapter := NewXKMSObjectAdapter(store)

	// Test success case
	testData := []byte("write test data")
	err = adapter.Write("adapter_test/write_test.txt", testData)
	assert.Nil(t, err)

	// Verify it was written
	readData, err := adapter.Read("adapter_test/write_test.txt")
	assert.Nil(t, err)
	assert.Equal(t, testData, readData)

	// Cleanup
	store.Delete([]byte("adapter_test/write_test.txt"))
}

// TestXKMSObjectAdapter_Delete tests the Delete method with success and error cases
func TestXKMSObjectAdapter_Delete(t *testing.T) {
	logger := logging.DefaultLogger()
	storage := NewMemoryClient()

	store, err := NewObjectStore(logger, storage, "tmp/testdata", nil)
	assert.Nil(t, err)

	adapter := NewXKMSObjectAdapter(store)

	// Test success case
	testData := []byte("delete test data")
	err = adapter.Write("adapter_test/delete_test.txt", testData)
	assert.Nil(t, err)

	err = adapter.Delete("adapter_test/delete_test.txt")
	assert.Nil(t, err)

	// Verify it was deleted
	_, err = adapter.Read("adapter_test/delete_test.txt")
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))

	// Test error case - delete non-existent
	err = adapter.Delete("adapter_test/nonexistent.txt")
	assert.NotNil(t, err)
	assert.True(t, errors.Is(err, ErrObjectNotFound))
}

// TestNewXKMSObjectAdapter tests the constructor
func TestNewXKMSObjectAdapter(t *testing.T) {
	logger := logging.DefaultLogger()
	storage := NewMemoryClient()

	store, err := NewObjectStore(logger, storage, "tmp/testdata", nil)
	assert.Nil(t, err)

	adapter := NewXKMSObjectAdapter(store)
	assert.NotNil(t, adapter)
	assert.Equal(t, store, adapter.store)
}
