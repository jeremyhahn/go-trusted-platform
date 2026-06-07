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

package registry

import (
	"context"
	"testing"
)

func TestFileStorageClient_PutGetDelete(t *testing.T) {
	c, err := NewFileStorageClient(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileStorageClient: %v", err)
	}
	ctx := context.Background()

	if err := c.Put(ctx, "blobs", "abc:def", []byte("hello"), 0); err != nil {
		t.Fatalf("Put: %v", err)
	}
	data, ok, err := c.Get(ctx, "blobs", "abc:def")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok || string(data) != "hello" {
		t.Errorf("Get returned (%q, %v)", data, ok)
	}
	if err := c.Delete(ctx, "blobs", "abc:def"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, ok, err = c.Get(ctx, "blobs", "abc:def")
	if err != nil {
		t.Errorf("Get after delete: unexpected error %v", err)
	}
	if ok {
		t.Error("Get after delete returned ok=true")
	}
}

func TestFileStorageClient_GetMissing(t *testing.T) {
	c, _ := NewFileStorageClient(t.TempDir())
	_, ok, err := c.Get(context.Background(), "blobs", "nope")
	if err != nil {
		t.Errorf("expected nil error for missing key, got %v", err)
	}
	if ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestFileStorageClient_List(t *testing.T) {
	c, _ := NewFileStorageClient(t.TempDir())
	ctx := context.Background()
	keys := []string{"alpha:1", "alpha:2", "beta:1"}
	for _, k := range keys {
		if err := c.Put(ctx, "m", k, []byte(k), 0); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
	}
	got, _, _, err := c.List(ctx, "m", "alpha", 0, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 || got[0] != "alpha:1" || got[1] != "alpha:2" {
		t.Errorf("List = %v, want [alpha:1 alpha:2]", got)
	}
}

func TestFileStorageClient_ListPagination(t *testing.T) {
	c, _ := NewFileStorageClient(t.TempDir())
	ctx := context.Background()
	for _, k := range []string{"a", "b", "c", "d"} {
		_ = c.Put(ctx, "m", k, []byte(k), 0)
	}
	page1, next, more, err := c.List(ctx, "m", "", 2, "")
	if err != nil {
		t.Fatalf("List page1: %v", err)
	}
	if len(page1) != 2 || !more {
		t.Errorf("page1=%v more=%v", page1, more)
	}
	page2, _, _, _ := c.List(ctx, "m", "", 2, next)
	if len(page2) != 2 {
		t.Errorf("page2=%v", page2)
	}
}

func TestFileStorageClient_RoundTripsExoticKeys(t *testing.T) {
	c, _ := NewFileStorageClient(t.TempDir())
	ctx := context.Background()
	for _, k := range []string{"repo/x:tag", "sha256:" + repeat64("a"), "with space"} {
		if err := c.Put(ctx, "m", k, []byte(k), 0); err != nil {
			t.Fatalf("Put %s: %v", k, err)
		}
		got, ok, err := c.Get(ctx, "m", k)
		if err != nil || !ok || string(got) != k {
			t.Errorf("RoundTrip %s failed: ok=%v err=%v got=%q", k, ok, err, got)
		}
	}
	keys, _, _, err := c.List(ctx, "m", "", 0, "")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("expected 3 keys after roundtrip, got %v", keys)
	}
}
