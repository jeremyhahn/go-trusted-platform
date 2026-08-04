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

package barrier

import (
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// protoStrategyToStrategy maps proto BarrierStrategy to domain Strategy.
var protoStrategyToStrategy = map[platformv1.BarrierStrategy]Strategy{
	platformv1.BarrierStrategy_BARRIER_STRATEGY_UNSPECIFIED: StrategyUnspecified,
	platformv1.BarrierStrategy_BARRIER_STRATEGY_SINGLE_KEY:  StrategySingleKey,
	platformv1.BarrierStrategy_BARRIER_STRATEGY_SHAMIR:      StrategyShamir,
}

// StrategyFromProto converts a proto BarrierStrategy to a domain Strategy.
func StrategyFromProto(s platformv1.BarrierStrategy) Strategy {
	if strategy, ok := protoStrategyToStrategy[s]; ok {
		return strategy
	}
	return StrategyUnspecified
}

// InitResultFromProto converts a proto BarrierInitResponse to a domain InitResult.
func InitResultFromProto(resp *platformv1.BarrierInitResponse) *InitResult {
	if resp == nil {
		return nil
	}
	result := &InitResult{
		Strategy:    StrategyFromProto(resp.Strategy),
		RootToken:   resp.RootToken,
		Threshold:   resp.Threshold,
		SharesTotal: resp.SharesTotal,
		ShareCount:  resp.ShareCount,
	}
	if resp.InitializedAt != nil {
		t := resp.InitializedAt.AsTime()
		result.InitializedAt = &t
	}
	return result
}

// StatusResultFromProto converts a proto BarrierStatusResponse to a domain StatusResult.
func StatusResultFromProto(resp *platformv1.BarrierStatusResponse) *StatusResult {
	if resp == nil {
		return nil
	}
	result := &StatusResult{
		Initialized:    resp.Initialized,
		Sealed:         resp.Sealed,
		Strategy:       StrategyFromProto(resp.Strategy),
		Threshold:      resp.Threshold,
		SharesTotal:    resp.SharesTotal,
		SharesProvided: resp.SharesProvided,
	}
	if resp.InitializedAt != nil {
		t := resp.InitializedAt.AsTime()
		result.InitializedAt = &t
	}
	return result
}

// UnsealResultFromProto converts a proto BarrierUnsealResponse to a domain UnsealResult.
func UnsealResultFromProto(resp *platformv1.BarrierUnsealResponse) *UnsealResult {
	if resp == nil {
		return nil
	}
	return &UnsealResult{
		Sealed:          resp.Sealed,
		SharesProvided:  resp.SharesProvided,
		SharesThreshold: resp.SharesThreshold,
	}
}

// SealResultFromProto converts a proto BarrierSealResponse to a domain SealResult.
func SealResultFromProto(resp *platformv1.BarrierSealResponse) *SealResult {
	if resp == nil {
		return nil
	}
	return &SealResult{
		Sealed: resp.Sealed,
	}
}

// RekeyResultFromProto converts a proto BarrierRekeyResponse to a domain RekeyResult.
func RekeyResultFromProto(resp *platformv1.BarrierRekeyResponse) *RekeyResult {
	if resp == nil {
		return nil
	}
	return &RekeyResult{
		Strategy:    StrategyFromProto(resp.Strategy),
		Threshold:   resp.Threshold,
		SharesTotal: resp.SharesTotal,
		ShareCount:  resp.ShareCount,
	}
}
