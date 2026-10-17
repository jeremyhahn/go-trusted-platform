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

package mcp

import (
	"errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/errclass"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// codeClassRules classifies the tool error types (KMSError, DeviceError,
// ...) by the naming convention their Code strings follow: a code carrying
// one of these markers is of that class. No code carries two markers.
var codeClassRules = []struct {
	marker string
	class  codes.Code
}{
	{"_NOT_FOUND", codes.NotFound},
	{"_ALREADY_EXISTS", codes.AlreadyExists},
	{"_REQUIRED", codes.InvalidArgument},
	{"INVALID", codes.InvalidArgument},
	{"_DECODE", codes.InvalidArgument},
	{"_SERVICE_UNAVAILABLE", codes.Unavailable},
	{"_NOT_CONFIGURED", codes.Unavailable},
	{"_NOT_RUNNING", codes.FailedPrecondition},
	{"_NOT_INITIALIZED", codes.FailedPrecondition},
}

// codeClass returns the class of a tool error code, and codes.Unknown for a
// code that names a failure rather than a class (IPAM_ALLOCATION_FAILED).
func codeClass(code string) codes.Code {
	for _, rule := range codeClassRules {
		if strings.Contains(code, rule.marker) {
			return rule.class
		}
	}
	return codes.Unknown
}

// codeStatus is the gRPC status a tool error type reports from GRPCStatus.
func codeStatus(code, message string) *status.Status {
	return status.New(codeClass(code), message)
}

// sentinelClasses classifies the sentinel errors that carry no gRPC status
// of their own: platform sentinels a tool passes through from a service
// (the daemon's gRPC services translate them to the same classes) and this
// package's own errors.New sentinels.
var sentinelClasses = []struct {
	err   error
	class codes.Code
}{
	{datastore.ErrRecordNotFound, codes.NotFound},

	{ErrDeviceProfileNotConfigured, codes.Unavailable},
	{ErrBMCNotConfigured, codes.Unavailable},
	{ErrPXENotConfigured, codes.Unavailable},
	{ErrSwitchNotConfigured, codes.Unavailable},
	{ErrClusterNotConfigured, codes.Unavailable},
	{ErrEABNotConfigured, codes.Unavailable},
	{ErrInvitationNotConfigured, codes.Unavailable},
	{ErrPhase35NotConfigured, codes.Unavailable},
	{ErrProvisionNotConfigured, codes.Unavailable},
	{ErrProxyNotConfigured, codes.Unavailable},
	{ErrRegistryNotConfigured, codes.Unavailable},

	{ErrDeviceProfileIdentityRequired, codes.InvalidArgument},
	{ErrDeviceProfileMatchCriteriaRequired, codes.InvalidArgument},
	{ErrDeviceProfileConfigIdentityRequired, codes.InvalidArgument},
	{ErrEABCredentialIDRequired, codes.InvalidArgument},
	{ErrEABKeyIDRequired, codes.InvalidArgument},
	{ErrEABHMACKeyRequired, codes.InvalidArgument},
	{ErrEABProfileIDRequired, codes.InvalidArgument},
	{ErrEABTenantIDRequired, codes.InvalidArgument},
	{ErrProvisionSessionIDRequired, codes.InvalidArgument},
	{ErrProvisionDigestRequired, codes.InvalidArgument},
	{ErrProxyIDRequired, codes.InvalidArgument},
	{ErrProxyRouteRequired, codes.InvalidArgument},
	{ErrProxyPoolRequired, codes.InvalidArgument},
	{ErrRegistryRepositoryRequired, codes.InvalidArgument},
	{ErrRegistryReferenceRequired, codes.InvalidArgument},
}

// toolErrorCode is the JSON-RPC code the server answers a failed tool call
// or resource read with. An error that carries a gRPC status (GRPCStatus,
// anywhere in its chain) is classified by it, a known sentinel by its
// class, and anything else by the classifier every transport shares
// (errclass: SDK and database errors by their class, the rest Internal).
func toolErrorCode(err error) int {
	if class := status.Code(err); class != codes.Unknown {
		return mcpwire.CodeForClass(class)
	}
	for _, sentinel := range sentinelClasses {
		if errors.Is(err, sentinel.err) {
			return mcpwire.CodeForClass(sentinel.class)
		}
	}
	return mcpwire.CodeForClass(errclass.Code(err))
}

// ErrInvalidArgument reports a tool argument the caller got wrong: absent
// when it is required, or not decodable (a base64 field that is not
// base64). It is InvalidArgument on every transport.
type ErrInvalidArgument struct {
	Msg   string
	Cause error
}

// Error returns the message, followed by the cause when there is one.
func (e ErrInvalidArgument) Error() string {
	if e.Cause == nil {
		return e.Msg
	}
	return e.Msg + ": " + e.Cause.Error()
}

// Unwrap returns the decode failure, if any.
func (e ErrInvalidArgument) Unwrap() error {
	return e.Cause
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrInvalidArgument) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}
