package helpers

import (
	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdkerrors "github.com/jeremyhahn/go-quicbaas/sdk/go/errors"
)

// KVEntityAbsent reports whether a KV Get answered "no such entity". The SDK
// carries that answer in three forms: a GetResponse whose Found is false, a
// transport's typed NotFound error, and the database NotFound error the
// embedded transport passes through unmapped. Any other error is a failure,
// not an absence.
func KVEntityAbsent(resp *quicbaassdk.GetResponse, err error) bool {
	if err != nil {
		return sdkerrors.IsNotFound(err) || quicbaassdk.IsDatabaseErrorCode(err, quicbaassdk.ErrNotFound)
	}
	return resp != nil && !resp.Found
}
