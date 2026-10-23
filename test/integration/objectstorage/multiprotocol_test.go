// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build integration

package objectstorage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// TestObjectStorageMultiProtocol runs the same object lifecycle through
// platformctl and each SDK protocol against a running platformd.
func TestObjectStorageMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	adapters := []ObjectStorageCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "objectstorage", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Logf("Warning: teardown error for %s: %v", adapter.Name(), err)
				}
			})
			runObjectStorageScenario(t, ctx, adapter)
		})
	}
}

// scenarioObjects tracks the keys a scenario stored, so a failed run still
// removes what it wrote.
type scenarioObjects struct {
	cmd    ObjectStorageCommands
	stored map[string]bool
}

// remember records a stored key.
func (s *scenarioObjects) remember(key string) { s.stored[key] = true }

// forget records a deleted key.
func (s *scenarioObjects) forget(key string) { delete(s.stored, key) }

// cleanup deletes every key still stored.
func (s *scenarioObjects) cleanup(t *testing.T, ctx context.Context) {
	for key := range s.stored {
		cctx, cancel := ShortContext(ctx)
		if _, err := s.cmd.Delete(cctx, &platformv1.DeleteObjectRequest{Key: key}); err != nil {
			t.Logf("Warning: %s could not delete %s: %v", s.cmd.Name(), key, err)
		}
		cancel()
	}
}

// runObjectStorageScenario stores an object, reads it back every way the
// service offers, copies it, finds it by tag and deletes both copies.
func runObjectStorageScenario(t *testing.T, ctx context.Context, cmd ObjectStorageCommands) {
	t.Helper()

	// Each transport writes under its own prefix with a run-unique tag, so
	// the listings see only this run's objects.
	run := fmt.Sprintf("%s-%d", strings.ToLower(cmd.Name()), time.Now().UnixNano())
	prefix := "itest:" + run + "/"
	key := prefix + "object.txt"
	copyKey := prefix + "copy.txt"
	value := []byte("object storage over " + cmd.Name())
	checksum := sha256.Sum256(value)

	objects := &scenarioObjects{cmd: cmd, stored: map[string]bool{}}
	t.Cleanup(func() { objects.cleanup(t, ctx) })

	t.Run("Put", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		put, err := cmd.Put(cctx, &platformv1.PutObjectRequest{
			Key:           key,
			Value:         value,
			ContentType:   "text/plain",
			Tags:          map[string]string{"itest-run": run},
			TargetBackend: testBackend,
		})
		requireCall(t, cmd, "Put", err)
		objects.remember(key)
		if put.GetKey() != key {
			t.Fatalf("%s Put: key %q, want %q", cmd.Name(), put.GetKey(), key)
		}
		if put.GetSize() != int64(len(value)) {
			t.Fatalf("%s Put: size %d, want %d", cmd.Name(), put.GetSize(), len(value))
		}
		if !bytes.Equal(put.GetChecksum(), checksum[:]) {
			t.Fatalf("%s Put: checksum %x, want the SHA-256 %x", cmd.Name(), put.GetChecksum(), checksum)
		}
	})

	t.Run("PutWithoutBackendIsRefused", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		_, err := cmd.Put(cctx, &platformv1.PutObjectRequest{Key: prefix + "no-backend.txt", Value: value})
		if err == nil {
			objects.remember(prefix + "no-backend.txt")
			t.Fatalf("%s Put without target_backend succeeded, want INVALID_ARGUMENT", cmd.Name())
		}
		if !IsInvalid(err) {
			t.Fatalf("%s Put without target_backend: %v, want INVALID_ARGUMENT", cmd.Name(), err)
		}
	})

	t.Run("Head", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		head, err := cmd.Head(cctx, &platformv1.HeadObjectRequest{Key: key})
		requireCall(t, cmd, "Head", err)
		if !head.GetExists() {
			t.Fatalf("%s Head: %s does not exist after the put", cmd.Name(), key)
		}
		if head.GetSize() != int64(len(value)) || head.GetContentType() != "text/plain" {
			t.Fatalf("%s Head: size %d content type %q, want %d and text/plain",
				cmd.Name(), head.GetSize(), head.GetContentType(), len(value))
		}
	})

	t.Run("Get", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		got, err := cmd.Get(cctx, &platformv1.GetObjectRequest{Key: key, IncludeMetadata: true})
		requireCall(t, cmd, "Get", err)
		if !bytes.Equal(got.GetValue(), value) {
			t.Fatalf("%s Get: value %q, want %q", cmd.Name(), got.GetValue(), value)
		}
		if got.GetTags()["itest-run"] != run {
			t.Fatalf("%s Get: tags %v, want itest-run=%s", cmd.Name(), got.GetTags(), run)
		}
	})

	t.Run("List", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		list, err := cmd.List(cctx, &platformv1.ListObjectsRequest{Prefix: prefix, IncludeTags: true})
		requireCall(t, cmd, "List", err)
		requireListed(t, cmd, "List", list, key)
	})

	t.Run("Copy", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		copied, err := cmd.Copy(cctx, &platformv1.CopyObjectRequest{
			SourceKey:      key,
			DestinationKey: copyKey,
			TargetBackend:  testBackend,
		})
		requireCall(t, cmd, "Copy", err)
		objects.remember(copyKey)
		if copied.GetKey() != copyKey || copied.GetSize() != int64(len(value)) {
			t.Fatalf("%s Copy: key %q size %d, want %q and %d",
				cmd.Name(), copied.GetKey(), copied.GetSize(), copyKey, len(value))
		}
	})

	t.Run("ListByTag", func(t *testing.T) {
		cctx, cancel := ShortContext(ctx)
		defer cancel()

		list, err := cmd.ListByTag(cctx, &platformv1.ListObjectsByTagRequest{TagName: "itest-run", TagValue: run})
		requireCall(t, cmd, "ListByTag", err)
		requireListed(t, cmd, "ListByTag", list, key)
	})

	t.Run("Delete", func(t *testing.T) {
		for _, k := range []string{key, copyKey} {
			cctx, cancel := ShortContext(ctx)
			deleted, err := cmd.Delete(cctx, &platformv1.DeleteObjectRequest{Key: k})
			cancel()
			requireCall(t, cmd, "Delete", err)
			objects.forget(k)
			if !deleted.GetDeleted() {
				t.Fatalf("%s Delete: %s reported not deleted", cmd.Name(), k)
			}
		}
	})
}

// requireCall fails the test on a call error, naming a missing service as a
// missing prerequisite rather than a broken call.
func requireCall(t *testing.T, cmd ObjectStorageCommands, op string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if IsNotConfigured(err) {
		t.Fatalf("missing prerequisite: %v", ErrObjectStorageNotConfigured{Transport: cmd.Name(), Err: err})
	}
	t.Fatalf("%s %s: %v", cmd.Name(), op, err)
}

// requireListed fails the test unless the listing holds key.
func requireListed(t *testing.T, cmd ObjectStorageCommands, op string, list *platformv1.ListObjectsResponse, key string) {
	t.Helper()
	for _, object := range list.GetObjects() {
		if object.GetKey() == key {
			return
		}
	}
	t.Fatalf("%s %s: %s not in %v", cmd.Name(), op, key, list.GetObjects())
}
