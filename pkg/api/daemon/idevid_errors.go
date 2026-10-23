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

package daemon

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrIDevIDServiceNotConfigured is returned by a transport whose shared
// IDevIDGRPCService has not been injected, so it cannot serve the IDevID and
// IAK operations.
type ErrIDevIDServiceNotConfigured struct{}

// Error implements the error interface.
func (ErrIDevIDServiceNotConfigured) Error() string {
	return "idevid: IDevID service not configured for this transport"
}

// GRPCStatus classifies the error as Unavailable.
func (e ErrIDevIDServiceNotConfigured) GRPCStatus() *status.Status {
	return status.New(codes.Unavailable, e.Error())
}

// ErrDeviceIdentityKeyNotDeletable is returned by DeleteIDevID and DeleteIAK,
// and by the TPM service's DeleteAK, which names the same IAK.
// The service does not evict the persistent 802.1AR key from the TPM, so it
// refuses instead of reporting a deletion that did not happen. Nothing is
// changed; the key's certificate is removed by its own delete-certificate
// operation.
type ErrDeviceIdentityKeyNotDeletable struct {
	// Key names the refused key: "IDevID" or "IAK".
	Key string
}

// Error implements the error interface.
func (e ErrDeviceIdentityKeyNotDeletable) Error() string {
	return "idevid: the " + e.Key + " key is TPM-resident and is not evicted by this service; " +
		"nothing was deleted (delete its certificate with Delete" + e.Key + "Certificate)"
}

// GRPCStatus classifies the refusal as FailedPrecondition.
func (e ErrDeviceIdentityKeyNotDeletable) GRPCStatus() *status.Status {
	return status.New(codes.FailedPrecondition, e.Error())
}
