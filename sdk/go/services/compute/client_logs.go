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
	"io"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// GetContainerLogsParams contains parameters for getting container logs.
type GetContainerLogsParams struct {
	// ID is the container identifier.
	ID string
	// Follow enables streaming of new log entries.
	Follow bool
	// TailLines limits output to the last N lines (0 = all).
	TailLines uint32
	// Stdout includes stdout log stream.
	Stdout bool
	// Stderr includes stderr log stream.
	Stderr bool
	// Since returns log entries at or after this time (zero value = no lower bound).
	Since time.Time
	// Until returns log entries at or before this time (zero value = no upper bound).
	Until time.Time
	// Timestamps prefixes each log line with its timestamp.
	Timestamps bool
}

// LogStreamCallback is called for each log entry received from the stream.
// Return a non-nil error to stop the stream.
type LogStreamCallback func(entry *LogEntry) error

// GetContainerLogsDomain streams container logs, invoking the callback for each entry.
// The callback receives domain LogEntry types. Streaming ends when the server
// closes the stream (io.EOF) or when the callback returns an error.
func (c *Client) GetContainerLogsDomain(ctx context.Context, params *GetContainerLogsParams, cb LogStreamCallback) error {
	if params == nil || params.ID == "" {
		return &ErrGetContainerLogsFailed{ID: "", Cause: ErrContainerIDRequired}
	}

	req := &platformv1.GetContainerLogsRequest{
		Id:         params.ID,
		Follow:     params.Follow,
		TailLines:  params.TailLines,
		Stdout:     params.Stdout,
		Stderr:     params.Stderr,
		Timestamps: params.Timestamps,
	}
	if !params.Since.IsZero() {
		req.Since = timestamppb.New(params.Since)
	}
	if !params.Until.IsZero() {
		req.Until = timestamppb.New(params.Until)
	}

	stream, err := c.grpc.GetContainerLogs(ctx, req)
	if err != nil {
		return &ErrGetContainerLogsFailed{ID: params.ID, Cause: err}
	}

	for {
		entry, recvErr := stream.Recv()
		if recvErr == io.EOF {
			return nil
		}
		if recvErr != nil {
			return &ErrGetContainerLogsFailed{ID: params.ID, Cause: recvErr}
		}

		domainEntry := logEntryFromProto(entry)
		if cbErr := cb(domainEntry); cbErr != nil {
			return cbErr
		}
	}
}

// GetContainerLogsBatch retrieves all container logs and returns them as a slice.
func (c *Client) GetContainerLogsBatch(ctx context.Context, params *GetContainerLogsParams) ([]*LogEntry, error) {
	var entries []*LogEntry
	err := c.GetContainerLogsDomain(ctx, params, func(entry *LogEntry) error {
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}
