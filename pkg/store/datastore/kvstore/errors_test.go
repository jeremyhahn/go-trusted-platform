package kvstore

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// TestErrNotFound_IsRecordNotFound pins that a DAO miss is a
// datastore.ErrRecordNotFound, bare and wrapped, so callers that test for the
// shared sentinel (the JWT revocation store) read a miss as a miss.
func TestErrNotFound_IsRecordNotFound(t *testing.T) {
	err := ErrNotFound{EntityType: "Blob", ID: 1}
	assert.True(t, errors.Is(err, datastore.ErrRecordNotFound))
	assert.True(t, errors.Is(fmt.Errorf("wrap: %w", err), datastore.ErrRecordNotFound))

	var nf ErrNotFound
	assert.True(t, errors.As(fmt.Errorf("wrap: %w", err), &nf))
	assert.Equal(t, uint64(1), nf.ID)
}

func TestErrNotFound_Error(t *testing.T) {
	err := ErrNotFound{EntityType: "User", ID: 42}
	assert.Contains(t, err.Error(), "entity not found")
	assert.Contains(t, err.Error(), "User")
	assert.Contains(t, err.Error(), "42")
}

func TestErrNotFoundByIndex_Error(t *testing.T) {
	err := ErrNotFoundByIndex{EntityType: "Invitation", IndexField: "Token", Value: "abc123"}
	assert.Contains(t, err.Error(), "entity not found by index")
	assert.Contains(t, err.Error(), "Invitation")
	assert.Contains(t, err.Error(), "Token")
	assert.Contains(t, err.Error(), "abc123")
}

func TestErrSerializationFailed_Error(t *testing.T) {
	cause := errors.New("json: unsupported type")
	err := ErrSerializationFailed{EntityType: "Role", Cause: cause}
	assert.Contains(t, err.Error(), "serialization failed")
	assert.Contains(t, err.Error(), "Role")
	assert.Contains(t, err.Error(), "json: unsupported type")
}

func TestErrSerializationFailed_Unwrap(t *testing.T) {
	cause := errors.New("json: unsupported type")
	err := ErrSerializationFailed{EntityType: "Role", Cause: cause}
	assert.ErrorIs(t, err, cause)
}

func TestErrDeserializationFailed_Error(t *testing.T) {
	cause := errors.New("unexpected EOF")
	err := ErrDeserializationFailed{EntityType: "User", Cause: cause}
	assert.Contains(t, err.Error(), "deserialization failed")
	assert.Contains(t, err.Error(), "User")
	assert.Contains(t, err.Error(), "unexpected EOF")
}

func TestErrDeserializationFailed_Unwrap(t *testing.T) {
	cause := errors.New("unexpected EOF")
	err := ErrDeserializationFailed{EntityType: "User", Cause: cause}
	assert.ErrorIs(t, err, cause)
}

func TestErrInvalidEntityID_Error(t *testing.T) {
	err := ErrInvalidEntityID{EntityType: "Blob", Reason: "cannot delete entity with ID 0"}
	assert.Contains(t, err.Error(), "invalid entity ID")
	assert.Contains(t, err.Error(), "Blob")
	assert.Contains(t, err.Error(), "cannot delete entity with ID 0")
}

func TestErrFactoryClosed_Error(t *testing.T) {
	err := ErrFactoryClosed{}
	assert.Contains(t, err.Error(), "kvstore factory is closed")
}
