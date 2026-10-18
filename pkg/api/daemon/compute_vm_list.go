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
	"slices"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmListOrders are the sort_by fields ListVMs accepts. An unset sort_by
// orders by id ascending. Ties on name or created_at fall back to id, so
// every order is total and a page walk sees each VM exactly once.
var vmListOrders = pageOrder[*platformv1.VM]{
	"":   vmListByID,
	"id": vmListByID,
	"name": func(a, b *platformv1.VM) bool {
		if a.GetConfig().GetName() == b.GetConfig().GetName() {
			return vmListByID(a, b)
		}
		return a.GetConfig().GetName() < b.GetConfig().GetName()
	},
	"created_at": func(a, b *platformv1.VM) bool {
		aCreated, bCreated := a.GetCreatedAt().AsTime(), b.GetCreatedAt().AsTime()
		if aCreated.Equal(bCreated) {
			return vmListByID(a, b)
		}
		return aCreated.Before(bCreated)
	},
}

// vmListByID orders VMs by id.
func vmListByID(a, b *platformv1.VM) bool { return a.GetId() < b.GetId() }

// validateVMListFilter refuses a ListVMs filter the service cannot apply: a
// state the VMState enum does not define, or a selector match_expressions
// entry, whose syntax the API does not define.
func validateVMListFilter(req *platformv1.ListVMsRequest) error {
	for _, state := range req.GetStates() {
		if _, ok := platformv1.VMState_name[int32(state)]; !ok {
			return ErrVMListUnknownState{State: int32(state)}
		}
	}
	if expressions := req.GetSelector().GetMatchExpressions(); len(expressions) > 0 {
		return ErrVMListSelectorExpression{Expression: expressions[0]}
	}
	return nil
}

// vmMatchesListFilter reports whether a VM is in one of the listed states (an
// empty list matches every state) and carries every match_labels pair.
func vmMatchesListFilter(vm *platformv1.VM, req *platformv1.ListVMsRequest) bool {
	if states := req.GetStates(); len(states) > 0 && !slices.Contains(states, vm.GetState()) {
		return false
	}
	labels := vm.GetConfig().GetLabels()
	for key, want := range req.GetSelector().GetMatchLabels() {
		if got, ok := labels[key]; !ok || got != want {
			return false
		}
	}
	return true
}
