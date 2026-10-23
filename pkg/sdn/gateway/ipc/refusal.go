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

package ipc

import (
	"errors"
	"math"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/nat64"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/perf"
)

// sentinelRefusals pairs each sentinel service error an API transport maps
// with its refusal class. The table is both directions of the codec: the
// child classifies with errors.Is, the caller rebuilds an error wrapping
// the same sentinel.
var sentinelRefusals = []struct {
	class ipcv1.ServiceRefusalClass
	err   error
}{
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_NOT_STARTED, loadbalancer.ErrNotStarted},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_VIP_NOT_FOUND, loadbalancer.ErrVIPNotFound},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_BACKEND_NOT_FOUND, loadbalancer.ErrBackendNotFound},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_VIP_EXISTS, loadbalancer.ErrVIPExists},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_ALGORITHM_UNSUPPORTED, loadbalancer.ErrAlgorithmUnsupported},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_INVALID_VIP_ADDRESS, loadbalancer.ErrInvalidVIPAddress},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_INVALID_VIP_PORT, loadbalancer.ErrInvalidVIPPort},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_INVALID_PROTOCOL, loadbalancer.ErrInvalidProtocol},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_NO_BACKENDS, loadbalancer.ErrNoBackends},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_TOO_MANY_BACKENDS, loadbalancer.ErrTooManyBackends},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_INVALID_BACKEND, loadbalancer.ErrInvalidBackend},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_LB_DUPLICATE_BACKEND, loadbalancer.ErrDuplicateBackend},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_NAT64_NOT_STARTED, nat64.ErrNotStarted},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_PERF_NO_BRIDGE_AVAILABLE, perf.ErrNoBridgeAvailable},
	{ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_PERF_APPCTL_UNAVAILABLE, perf.ErrAppCtlUnavailable},
}

// sentinelByClass is sentinelRefusals keyed by class, for the caller.
var sentinelByClass = func() map[ipcv1.ServiceRefusalClass]error {
	m := make(map[ipcv1.ServiceRefusalClass]error, len(sentinelRefusals))
	for _, s := range sentinelRefusals {
		m[s.class] = s.err
	}
	return m
}()

// typedRefusalEncoders classify the struct service errors that carry
// fields. Each fills the refusal and reports whether err was its type.
var typedRefusalEncoders = []func(err error, r *ipcv1.ServiceRefusal) bool{
	func(err error, r *ipcv1.ServiceRefusal) bool {
		var notActive *gateway.ErrServiceNotActive
		if !errors.As(err, &notActive) {
			return false
		}
		r.Class = ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_SERVICE_NOT_ACTIVE
		r.Service = notActive.Service
		return true
	},
	func(err error, r *ipcv1.ServiceRefusal) bool {
		var module *nat64.ErrNAT64ModuleUnavailable
		if !errors.As(err, &module) {
			return false
		}
		r.Class = ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_NAT64_MODULE_UNAVAILABLE
		r.Instance = module.Instance
		r.Cause = errorText(module.Err)
		return true
	},
	func(err error, r *ipcv1.ServiceRefusal) bool {
		var count *perf.ErrInvalidFlowCount
		if !errors.As(err, &count) {
			return false
		}
		r.Class = ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_PERF_INVALID_FLOW_COUNT
		r.Count = clampInt32(count.Count)
		r.Max = clampInt32(count.Max)
		return true
	},
	func(err error, r *ipcv1.ServiceRefusal) bool {
		var bridge *perf.ErrBridgeUnavailable
		if !errors.As(err, &bridge) {
			return false
		}
		r.Class = ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_PERF_BRIDGE_UNAVAILABLE
		r.Bridge = bridge.Bridge
		r.Cause = errorText(bridge.Cause)
		return true
	},
}

// typedRefusalDecoders rebuild the struct service errors from their
// refusal, keyed by class.
var typedRefusalDecoders = map[ipcv1.ServiceRefusalClass]func(r *ipcv1.ServiceRefusal) error{
	ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_SERVICE_NOT_ACTIVE: func(r *ipcv1.ServiceRefusal) error {
		return &gateway.ErrServiceNotActive{Service: r.GetService()}
	},
	ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_NAT64_MODULE_UNAVAILABLE: func(r *ipcv1.ServiceRefusal) error {
		return &nat64.ErrNAT64ModuleUnavailable{Instance: r.GetInstance(), Err: &ErrRemoteService{Message: r.GetCause()}}
	},
	ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_PERF_INVALID_FLOW_COUNT: func(r *ipcv1.ServiceRefusal) error {
		return &perf.ErrInvalidFlowCount{Count: int(r.GetCount()), Max: int(r.GetMax())}
	},
	ipcv1.ServiceRefusalClass_SERVICE_REFUSAL_CLASS_PERF_BRIDGE_UNAVAILABLE: func(r *ipcv1.ServiceRefusal) error {
		return &perf.ErrBridgeUnavailable{Bridge: r.GetBridge(), Cause: &ErrRemoteService{Message: r.GetCause()}}
	},
}

// refusalFor encodes a service error for the wire; nil for nil.
func refusalFor(err error) *ipcv1.ServiceRefusal {
	if err == nil {
		return nil
	}
	r := &ipcv1.ServiceRefusal{Message: err.Error()}
	for _, encode := range typedRefusalEncoders {
		if encode(err, r) {
			return r
		}
	}
	for _, s := range sentinelRefusals {
		if errors.Is(err, s.err) {
			r.Class = s.class
			return r
		}
	}
	return r
}

// errorForRefusal rebuilds the service error a refusal carries; nil for
// none. An unknown class is an untyped *ErrRemoteService.
func errorForRefusal(r *ipcv1.ServiceRefusal) error {
	if r == nil {
		return nil
	}
	if decode, ok := typedRefusalDecoders[r.GetClass()]; ok {
		return decode(r)
	}
	return &ErrRemoteService{Message: r.GetMessage(), Sentinel: sentinelByClass[r.GetClass()]}
}

// errorText is err's text, empty for nil.
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// clampInt32 narrows v to the int32 range of the wire field.
func clampInt32(v int) int32 {
	switch {
	case v > math.MaxInt32:
		return math.MaxInt32
	case v < math.MinInt32:
		return math.MinInt32
	default:
		return int32(v)
	}
}
