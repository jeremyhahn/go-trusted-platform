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

package tpm

import (
	"bytes"
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	idevidsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/idevid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// keyDeleteGRPC answers both key deletes with status and err.
type keyDeleteGRPC struct {
	platformv1.IDevIDServiceClient
	status *platformv1.Status
	err    error
}

func (f *keyDeleteGRPC) DeleteIDevID(context.Context, *platformv1.DeleteIDevIDRequest, ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteIDevIDResponse{Status: f.status}, nil
}

func (f *keyDeleteGRPC) DeleteIAK(context.Context, *platformv1.DeleteIAKRequest, ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &platformv1.DeleteIAKResponse{Status: f.status}, nil
}

// keyDeleteBase is a BaseCommandInterface over a keyDeleteGRPC that records
// what the command printed and whether it closed its connection.
type keyDeleteBase struct {
	client *idevidsvc.Client
	format cli.OutputFormat
	out    bytes.Buffer
	closed bool
}

func newKeyDeleteBase(grpcClient *keyDeleteGRPC, format cli.OutputFormat) *keyDeleteBase {
	return &keyDeleteBase{client: idevidsvc.NewClientFromGRPC(grpcClient), format: format}
}

func (b *keyDeleteBase) Client() IDevIDClientProvider { return b }
func (b *keyDeleteBase) IDevID() *idevidsvc.Client    { return b.client }
func (b *keyDeleteBase) Context() context.Context     { return context.Background() }
func (b *keyDeleteBase) Flags() *cli.CommonFlags      { return &cli.CommonFlags{OutputFormat: b.format} }
func (b *keyDeleteBase) Printer() *cli.Printer {
	return cli.NewPrinterWithWriter(b.format, true, &b.out)
}
func (b *keyDeleteBase) Close() error { b.closed = true; return nil }

var identityKeyDeleteRunners = map[string]func(BaseCommandInterface) error{
	"IDevID": runIDevIDDeleteWithClient,
	"IAK":    runIAKDeleteWithClient,
}

// TestIdentityKeyDelete_RefusalExitsNonZero pins #304 in the CLI: the
// daemon's refusal is a typed error (a non-zero exit) and nothing claiming
// a deletion is printed, in any output format.
func TestIdentityKeyDelete_RefusalExitsNonZero(t *testing.T) {
	refusal := status.Error(codes.FailedPrecondition, "the key is TPM-resident")
	for key, run := range identityKeyDeleteRunners {
		for _, format := range []cli.OutputFormat{cli.OutputFormatTable, cli.OutputFormatJSON} {
			base := newKeyDeleteBase(&keyDeleteGRPC{err: refusal}, format)

			err := run(base)

			var refused ErrIdentityKeyDeleteRefused
			require.ErrorAs(t, err, &refused, "%s %s", key, format)
			assert.Equal(t, key, refused.Key)
			assert.ErrorIs(t, err, refusal)
			assert.Equal(t, key+" key delete refused: the key is TPM-resident and is not evicted; nothing was changed", err.Error())
			assert.Empty(t, base.out.String(), "%s %s must print nothing", key, format)
			assert.True(t, base.closed)
		}
	}
}

func TestIdentityKeyDelete_OtherFailureIsNotARefusal(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "daemon down")
	failures := map[string]any{"IDevID": ErrDeleteIDevIDFailed{}, "IAK": ErrDeleteIAKFailed{}}
	for key, run := range identityKeyDeleteRunners {
		base := newKeyDeleteBase(&keyDeleteGRPC{err: unavailable}, cli.OutputFormatTable)

		err := run(base)

		require.Error(t, err)
		assert.IsType(t, failures[key], err, key)
		assert.Contains(t, err.Error(), "daemon down")
		assert.Empty(t, base.out.String())
	}
}

// TestIdentityKeyDelete_UnreportedDeleteFails guards the old exit-0 path: a
// reply that does not report the key deleted is a failure, not a success.
func TestIdentityKeyDelete_UnreportedDeleteFails(t *testing.T) {
	for key, run := range identityKeyDeleteRunners {
		base := newKeyDeleteBase(&keyDeleteGRPC{status: &platformv1.Status{Success: false, Message: "not deleted"}}, cli.OutputFormatJSON)

		err := run(base)

		require.Error(t, err, key)
		assert.Contains(t, err.Error(), "not deleted")
		assert.Empty(t, base.out.String())
	}
}

func TestIdentityKeyDelete_ReportedDeletePrints(t *testing.T) {
	for key, run := range identityKeyDeleteRunners {
		base := newKeyDeleteBase(&keyDeleteGRPC{status: &platformv1.Status{Success: true}}, cli.OutputFormatTable)

		require.NoError(t, run(base), key)
		assert.Contains(t, base.out.String(), key+" key deleted")
	}
}

func TestIdentityKeyDelete_InvalidOutputFormat(t *testing.T) {
	base := newKeyDeleteBase(&keyDeleteGRPC{status: &platformv1.Status{Success: true}}, cli.OutputFormat("xml"))

	err := runIDevIDDeleteWithClient(base)

	assert.IsType(t, cli.ErrInvalidOutputFormat{}, err)
}
