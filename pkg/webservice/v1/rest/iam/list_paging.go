package iam

import (
	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"
)

// listOffsetPage serves the records from offset on, limit at most, from a
// backend that pages by opaque token and has no offset of its own. fetch asks
// the backend for the page a token names (the empty token is the first page);
// the caller requests pages of limit records.
//
// The walk drops the records before offset and stops when limit records are
// collected, when the backend reports no more pages, or when the next token is
// empty or repeats the one just used. An offset past the end gives no records.
// The total is the backend's count from the last page read. An error from any
// page ends the walk and is returned as it is.
func listOffsetPage[T any](
	limit, offset int32,
	fetch func(pageToken string) ([]T, iamsdk.PaginationInfo, error),
) ([]T, int64, error) {
	records := make([]T, 0)
	skip := int(offset)
	pageToken := ""
	for {
		page, pagination, err := fetch(pageToken)
		if err != nil {
			return nil, 0, err
		}
		total := int64(pagination.TotalCount)
		for i := range page {
			if skip > 0 {
				skip--
				continue
			}
			if len(records) >= int(limit) {
				break
			}
			records = append(records, page[i])
		}
		if len(records) >= int(limit) {
			return records, total, nil
		}
		next := pagination.NextPageToken
		if !pagination.HasMore || next == "" || next == pageToken {
			return records, total, nil
		}
		pageToken = next
	}
}
