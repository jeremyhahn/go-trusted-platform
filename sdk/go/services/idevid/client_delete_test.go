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

package idevid

import (
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// keyDeleteGRPC answers both key deletes with err.
type keyDeleteGRPC struct {
	platformv1.IDevIDServiceClient
	err error
}

func (f *keyDeleteGRPC) DeleteIDevID(context.Context, *platformv1.DeleteIDevIDRequest, ...grpc.CallOption) (*platformv1.DeleteIDevIDResponse, error) {
	return nil, f.err
}

func (f *keyDeleteGRPC) DeleteIAK(context.Context, *platformv1.DeleteIAKRequest, ...grpc.CallOption) (*platformv1.DeleteIAKResponse, error) {
	return nil, f.err
}

// keyDeletes calls every SDK key delete for key ("IDevID" or "IAK").
func keyDeletes(c *Client, key string) map[string]func(context.Context) error {
	if key == "IAK" {
		return map[string]func(context.Context) error{
			"DeleteIAK": c.DeleteIAK,
			"DeleteIAKDomain": func(ctx context.Context) error {
				_, _, err := c.DeleteIAKDomain(ctx)
				return err
			},
		}
	}
	return map[string]func(context.Context) error{
		"DeleteIDevID": c.DeleteIDevID,
		"DeleteIDevIDDomain": func(ctx context.Context) error {
			_, _, err := c.DeleteIDevIDDomain(ctx)
			return err
		},
	}
}

func TestKeyDelete_RefusalIsTyped(t *testing.T) {
	refusal := status.Error(codes.FailedPrecondition, "the key is TPM-resident")
	client := NewClientFromGRPC(&keyDeleteGRPC{err: refusal})

	for _, key := range []string{"IDevID", "IAK"} {
		for name, deleteKey := range keyDeletes(client, key) {
			err := deleteKey(context.Background())
			var refused *ErrIdentityKeyNotDeletable
			require.ErrorAs(t, err, &refused, name)
			assert.Equal(t, key, refused.Key, name)
			assert.ErrorIs(t, err, refusal, name)
			assert.Equal(t, codes.FailedPrecondition, status.Code(err), name)
			assert.Contains(t, err.Error(), "key delete refused; the key stays in the TPM", name)
		}
	}
}

func TestKeyDelete_OtherFailureIsNotARefusal(t *testing.T) {
	unavailable := status.Error(codes.Unavailable, "daemon down")
	client := NewClientFromGRPC(&keyDeleteGRPC{err: unavailable})

	for _, key := range []string{"IDevID", "IAK"} {
		for name, deleteKey := range keyDeletes(client, key) {
			err := deleteKey(context.Background())
			var refused *ErrIdentityKeyNotDeletable
			assert.False(t, errors.As(err, &refused), name)
			assert.ErrorIs(t, err, unavailable, name)
			if key == "IAK" {
				assert.IsType(t, &ErrDeleteIAKFailed{}, err, name)
			} else {
				assert.IsType(t, &ErrDeleteIDevIDFailed{}, err, name)
			}
		}
	}
}
