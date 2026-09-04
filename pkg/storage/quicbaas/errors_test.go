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

	"github.com/stretchr/testify/assert"
)

func TestErrNotFound_Error(t *testing.T) {
	err := ErrNotFound{EntityType: "User", ID: 12345}
	assert.Equal(t, "entity not found: type=User, id=12345", err.Error())
}

func TestErrNotFound_ErrorAs(t *testing.T) {
	err := ErrNotFound{EntityType: "Role", ID: 999}

	var notFoundErr ErrNotFound
	assert.True(t, errors.As(err, &notFoundErr))
	assert.Equal(t, "Role", notFoundErr.EntityType)
	assert.Equal(t, uint64(999), notFoundErr.ID)
}

func TestErrNotFoundByIndex_Error(t *testing.T) {
	err := ErrNotFoundByIndex{EntityType: "Role", IndexField: "Name", Value: "admin"}
	assert.Equal(t, "entity not found by index: type=Role, Name=admin", err.Error())
}

func TestErrNotFoundByIndex_ErrorAs(t *testing.T) {
	err := ErrNotFoundByIndex{EntityType: "Zone", IndexField: "Domain", Value: "example.com"}

	var indexErr ErrNotFoundByIndex
	assert.True(t, errors.As(err, &indexErr))
	assert.Equal(t, "Zone", indexErr.EntityType)
	assert.Equal(t, "Domain", indexErr.IndexField)
	assert.Equal(t, "example.com", indexErr.Value)
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Field: "DataDir", Reason: "cannot be empty"}
	assert.Equal(t, "invalid configuration: DataDir: cannot be empty", err.Error())
}

func TestErrInvalidConfig_ErrorAs(t *testing.T) {
	err := ErrInvalidConfig{Field: "NodeID", Reason: "must be positive"}

	var configErr ErrInvalidConfig
	assert.True(t, errors.As(err, &configErr))
	assert.Equal(t, "NodeID", configErr.Field)
	assert.Equal(t, "must be positive", configErr.Reason)
}

func TestErrServerNotStarted_Error(t *testing.T) {
	err := ErrServerNotStarted{}
	assert.Equal(t, "quicbaas server not started", err.Error())
}

func TestErrServerNotStarted_ErrorAs(t *testing.T) {
	err := ErrServerNotStarted{}

	var notStartedErr ErrServerNotStarted
	assert.True(t, errors.As(err, &notStartedErr))
}

func TestErrServerClosed_Error(t *testing.T) {
	err := ErrServerClosed{}
	assert.Equal(t, "quicbaas server is closed", err.Error())
}

func TestErrServerClosed_ErrorAs(t *testing.T) {
	err := ErrServerClosed{}

	var closedErr ErrServerClosed
	assert.True(t, errors.As(err, &closedErr))
}

func TestErrConnectionFailed_Error(t *testing.T) {
	cause := errors.New("network timeout")
	err := ErrConnectionFailed{Cause: cause}
	assert.Equal(t, "quicbaas connection failed: network timeout", err.Error())
}

func TestErrConnectionFailed_Unwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrConnectionFailed{Cause: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrConnectionFailed_ErrorAs(t *testing.T) {
	err := ErrConnectionFailed{Cause: errors.New("timeout")}

	var connErr ErrConnectionFailed
	assert.True(t, errors.As(err, &connErr))
	assert.NotNil(t, connErr.Cause)
}

func TestErrOperationFailed_Error(t *testing.T) {
	cause := errors.New("disk full")
	err := ErrOperationFailed{Operation: "Put", Cause: cause}
	assert.Equal(t, "quicbaas operation failed: Put: disk full", err.Error())
}

func TestErrOperationFailed_Unwrap(t *testing.T) {
	cause := errors.New("permission denied")
	err := ErrOperationFailed{Operation: "Delete", Cause: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrOperationFailed_ErrorAs(t *testing.T) {
	err := ErrOperationFailed{Operation: "Get", Cause: errors.New("not found")}

	var opErr ErrOperationFailed
	assert.True(t, errors.As(err, &opErr))
	assert.Equal(t, "Get", opErr.Operation)
}

func TestErrOperationFailed_NilCause(t *testing.T) {
	err := ErrOperationFailed{Operation: "List", Cause: nil}
	assert.Equal(t, "quicbaas operation failed: List: <nil>", err.Error())
	assert.Nil(t, err.Unwrap())
}

func TestErrSerializationFailed_Error(t *testing.T) {
	cause := errors.New("json: unsupported type")
	err := ErrSerializationFailed{EntityType: "User", Cause: cause}
	assert.Equal(t, "serialization failed for User: json: unsupported type", err.Error())
}

func TestErrSerializationFailed_Unwrap(t *testing.T) {
	cause := errors.New("encoding error")
	err := ErrSerializationFailed{EntityType: "Role", Cause: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrSerializationFailed_ErrorAs(t *testing.T) {
	err := ErrSerializationFailed{EntityType: "Organization", Cause: errors.New("marshal error")}

	var serErr ErrSerializationFailed
	assert.True(t, errors.As(err, &serErr))
	assert.Equal(t, "Organization", serErr.EntityType)
}

func TestErrDeserializationFailed_Error(t *testing.T) {
	cause := errors.New("invalid json")
	err := ErrDeserializationFailed{EntityType: "Role", Cause: cause}
	assert.Equal(t, "deserialization failed for Role: invalid json", err.Error())
}

func TestErrDeserializationFailed_Unwrap(t *testing.T) {
	cause := errors.New("decoding error")
	err := ErrDeserializationFailed{EntityType: "User", Cause: cause}

	unwrapped := err.Unwrap()
	assert.Equal(t, cause, unwrapped)
	assert.True(t, errors.Is(err, cause))
}

func TestErrDeserializationFailed_ErrorAs(t *testing.T) {
	err := ErrDeserializationFailed{EntityType: "Registration", Cause: errors.New("unmarshal error")}

	var deserErr ErrDeserializationFailed
	assert.True(t, errors.As(err, &deserErr))
	assert.Equal(t, "Registration", deserErr.EntityType)
}

func TestErrInvalidEntityID_Error(t *testing.T) {
	err := ErrInvalidEntityID{EntityType: "User", Reason: "cannot delete entity with ID 0"}
	assert.Equal(t, "invalid entity ID for User: cannot delete entity with ID 0", err.Error())
}

func TestErrInvalidEntityID_ErrorAs(t *testing.T) {
	err := ErrInvalidEntityID{EntityType: "Role", Reason: "ID must be positive"}

	var idErr ErrInvalidEntityID
	assert.True(t, errors.As(err, &idErr))
	assert.Equal(t, "Role", idErr.EntityType)
	assert.Equal(t, "ID must be positive", idErr.Reason)
}

func TestErrRaftNotReady_Error(t *testing.T) {
	err := ErrRaftNotReady{Reason: "no leader elected"}
	assert.Equal(t, "raft not ready: no leader elected", err.Error())
}

func TestErrRaftNotReady_ErrorAs(t *testing.T) {
	err := ErrRaftNotReady{Reason: "cluster bootstrapping"}

	var raftErr ErrRaftNotReady
	assert.True(t, errors.As(err, &raftErr))
	assert.Equal(t, "cluster bootstrapping", raftErr.Reason)
}

func TestErrFactoryClosed_Error(t *testing.T) {
	err := ErrFactoryClosed{}
	assert.Equal(t, "quicbaas factory is closed", err.Error())
}

func TestErrFactoryClosed_ErrorAs(t *testing.T) {
	err := ErrFactoryClosed{}

	var closedErr ErrFactoryClosed
	assert.True(t, errors.As(err, &closedErr))
}

func TestErrContextCancelled_Error(t *testing.T) {
	err := ErrContextCancelled{Operation: "Save", Cause: context.Canceled}
	assert.Equal(t, "context cancelled for operation Save: context canceled", err.Error())
}

func TestErrContextCancelled_Unwrap(t *testing.T) {
	err := ErrContextCancelled{Operation: "Get", Cause: context.Canceled}

	unwrapped := err.Unwrap()
	assert.Equal(t, context.Canceled, unwrapped)
	assert.True(t, errors.Is(err, context.Canceled))
}

func TestErrContextCancelled_ErrorAs(t *testing.T) {
	err := ErrContextCancelled{Operation: "Delete", Cause: context.DeadlineExceeded}

	var ctxErr ErrContextCancelled
	assert.True(t, errors.As(err, &ctxErr))
	assert.Equal(t, "Delete", ctxErr.Operation)
	assert.Equal(t, context.DeadlineExceeded, ctxErr.Cause)
}

func TestAllErrors_ImplementError(t *testing.T) {
	// Verify all error types implement the error interface
	var errs []error
	errs = append(errs, ErrNotFound{})
	errs = append(errs, ErrNotFoundByIndex{})
	errs = append(errs, ErrInvalidConfig{})
	errs = append(errs, ErrServerNotStarted{})
	errs = append(errs, ErrServerClosed{})
	errs = append(errs, ErrConnectionFailed{})
	errs = append(errs, ErrOperationFailed{})
	errs = append(errs, ErrSerializationFailed{})
	errs = append(errs, ErrDeserializationFailed{})
	errs = append(errs, ErrInvalidEntityID{})
	errs = append(errs, ErrStartupCanceled{Cause: context.Canceled})
	errs = append(errs, ErrStartupTimeout{})
	errs = append(errs, ErrRaftNotReady{})
	errs = append(errs, ErrFactoryClosed{})
	errs = append(errs, ErrContextCancelled{Operation: "test", Cause: context.Canceled})

	for _, err := range errs {
		// Just verify they don't panic when calling Error()
		assert.NotEmpty(t, err.Error())
	}
}
