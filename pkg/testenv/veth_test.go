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

package testenv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVethQueuesIsOne(t *testing.T) {
	// One queue per end is the point of #1178: any more and a veth add or
	// remove fans out into per-queue uevents again.
	assert.Equal(t, 1, VethQueues)
}

func TestNewVethPinsBothEndsToOneQueue(t *testing.T) {
	veth := NewVeth("v0", "v1")

	assert.Equal(t, "v0", veth.Name)
	assert.Equal(t, "v1", veth.PeerName)
	assert.Equal(t, "veth", veth.Type())
	assert.Equal(t, VethQueues, veth.NumTxQueues, "local tx queues")
	assert.Equal(t, VethQueues, veth.NumRxQueues, "local rx queues")
	assert.Equal(t, uint32(VethQueues), veth.PeerNumTxQueues, "peer tx queues")
	assert.Equal(t, uint32(VethQueues), veth.PeerNumRxQueues, "peer rx queues")
}

func TestNewVethKeepsKernelDefaultsForOtherAttrs(t *testing.T) {
	// The link attributes start from netlink.NewLinkAttrs, so the unset
	// TxQLen stays -1 (kernel default) instead of 0, which would create a
	// veth with no transmit queue length at all.
	veth := NewVeth("v0", "v1")

	assert.Equal(t, -1, veth.TxQLen)
	assert.Nil(t, veth.PeerNamespace)
}

func TestVethArgsPinsBothEndsToOneQueue(t *testing.T) {
	assert.Equal(t, []string{
		"link", "add", "name", "v0", "numtxqueues", "1", "numrxqueues", "1",
		"type", "veth", "peer", "name", "v1", "numtxqueues", "1", "numrxqueues", "1",
	}, VethArgs("v0", "v1"))
}

func TestVethNetnsArgsPlacesEachEnd(t *testing.T) {
	assert.Equal(t, []string{
		"link", "add", "name", "v0", "netns", "nsa", "numtxqueues", "1", "numrxqueues", "1",
		"type", "veth", "peer", "name", "v1", "netns", "nsb", "numtxqueues", "1", "numrxqueues", "1",
	}, VethNetnsArgs("v0", "nsa", "v1", "nsb"))
}

func TestVethNetnsArgsEmptyNamespaceStaysLocal(t *testing.T) {
	args := VethNetnsArgs("v0", "", "v1", "nsb")

	assert.Equal(t, []string{
		"link", "add", "name", "v0", "numtxqueues", "1", "numrxqueues", "1",
		"type", "veth", "peer", "name", "v1", "netns", "nsb", "numtxqueues", "1", "numrxqueues", "1",
	}, args)
}
