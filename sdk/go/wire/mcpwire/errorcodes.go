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

package mcpwire

import "google.golang.org/grpc/codes"

// codeForClass is the one table that turns a platform error class into a
// JSON-RPC error code. The server answers a failed tool call with the code
// for the error's class; anything not listed is InternalError.
var codeForClass = map[codes.Code]int{
	codes.InvalidArgument:    InvalidParams,
	codes.Unauthenticated:    AuthenticationRequired,
	codes.PermissionDenied:   PermissionDenied,
	codes.Unavailable:        ServiceUnavailable,
	codes.NotFound:           NotFound,
	codes.AlreadyExists:      AlreadyExists,
	codes.FailedPrecondition: FailedPrecondition,
}

// classForCode is the inverse a client uses to decode a JSON-RPC error
// code. It also covers the protocol codes a server answers without a tool
// error behind them.
var classForCode = map[int]codes.Code{
	ParseError:             codes.InvalidArgument,
	InvalidRequest:         codes.InvalidArgument,
	MethodNotFound:         codes.Unimplemented,
	InvalidParams:          codes.InvalidArgument,
	InternalError:          codes.Internal,
	AuthenticationRequired: codes.Unauthenticated,
	InvalidToken:           codes.Unauthenticated,
	PermissionDenied:       codes.PermissionDenied,
	ServiceUnavailable:     codes.Unavailable,
	NotFound:               codes.NotFound,
	AlreadyExists:          codes.AlreadyExists,
	FailedPrecondition:     codes.FailedPrecondition,
}

// CodeForClass returns the JSON-RPC error code for a platform error class;
// a class the table does not name is InternalError.
func CodeForClass(class codes.Code) int {
	if code, ok := codeForClass[class]; ok {
		return code
	}
	return InternalError
}

// ClassForCode returns the platform error class a JSON-RPC error code
// stands for, and codes.Unknown for a code the platform does not define.
func ClassForCode(code int) codes.Code {
	if class, ok := classForCode[code]; ok {
		return class
	}
	return codes.Unknown
}
