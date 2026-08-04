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
	"errors"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestGetContainerLogsDomain_SinceUntilTimestamps(t *testing.T) {
	since := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	until := time.Now().UTC().Truncate(time.Second)

	fake := &fakeComputeClient{
		logsEntries: []*platformv1.LogEntry{
			{Message: "line-1"},
			{Message: "line-2"},
		},
	}
	client := NewClientFromGRPC(fake)

	entries, err := client.GetContainerLogsBatch(context.Background(), &GetContainerLogsParams{
		ID:         "c-1",
		Stdout:     true,
		Stderr:     true,
		TailLines:  10,
		Since:      since,
		Until:      until,
		Timestamps: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got: %d", len(entries))
	}
	if entries[0].Message != "line-1" || entries[1].Message != "line-2" {
		t.Errorf("unexpected entries: %+v", entries)
	}

	req := fake.logsReq
	if req == nil {
		t.Fatal("expected request captured")
	}
	if req.GetSince() == nil || !req.GetSince().AsTime().Equal(since) {
		t.Errorf("expected since %v, got: %v", since, req.GetSince())
	}
	if req.GetUntil() == nil || !req.GetUntil().AsTime().Equal(until) {
		t.Errorf("expected until %v, got: %v", until, req.GetUntil())
	}
	if !req.GetTimestamps() {
		t.Error("expected timestamps enabled in request")
	}
	if req.GetTailLines() != 10 {
		t.Errorf("expected tail_lines 10, got: %d", req.GetTailLines())
	}
}

func TestGetContainerLogsDomain_ZeroTimeBoundsOmitted(t *testing.T) {
	fake := &fakeComputeClient{}
	client := NewClientFromGRPC(fake)

	_, err := client.GetContainerLogsBatch(context.Background(), &GetContainerLogsParams{
		ID:     "c-1",
		Stdout: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := fake.logsReq
	if req == nil {
		t.Fatal("expected request captured")
	}
	if req.GetSince() != nil {
		t.Errorf("expected nil since for zero time, got: %v", req.GetSince())
	}
	if req.GetUntil() != nil {
		t.Errorf("expected nil until for zero time, got: %v", req.GetUntil())
	}
	if req.GetTimestamps() {
		t.Error("expected timestamps disabled by default")
	}
}

func TestGetContainerLogsDomain_MissingID(t *testing.T) {
	client := NewClientFromGRPC(&fakeComputeClient{})

	err := client.GetContainerLogsDomain(context.Background(), &GetContainerLogsParams{}, func(entry *LogEntry) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for missing container ID")
	}
	if !errors.Is(err, ErrContainerIDRequired) {
		t.Errorf("expected ErrContainerIDRequired cause, got: %v", err)
	}
}

func TestGetContainerLogsDomain_RPCError(t *testing.T) {
	fake := &fakeComputeClient{logsErr: errors.New("rpc failed")}
	client := NewClientFromGRPC(fake)

	_, err := client.GetContainerLogsBatch(context.Background(), &GetContainerLogsParams{ID: "c-1"})
	if err == nil {
		t.Fatal("expected error")
	}
	var logsErr *ErrGetContainerLogsFailed
	if !errors.As(err, &logsErr) {
		t.Fatalf("expected ErrGetContainerLogsFailed, got: %T", err)
	}
}
