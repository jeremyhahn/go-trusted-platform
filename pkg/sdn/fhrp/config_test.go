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

package fhrp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGroupConfig_Validate(t *testing.T) {
	good := backupConfig()
	require.NoError(t, good.Validate())
	assert.Equal(t, uint8(100), good.effectivePriority())
	assert.Equal(t, uint16(100), good.effectiveInterval())
	assert.True(t, good.preempts())
	assert.Equal(t, FamilyIPv4, good.family())

	defaults := good
	defaults.Priority, defaults.AdvertIntervalCentiseconds = 0, 0
	assert.Equal(t, uint8(PriorityDefault), defaults.effectivePriority())
	assert.Equal(t, uint16(DefaultAdvertIntervalCentiseconds), defaults.effectiveInterval())

	v6 := GroupConfig{VRID: 1, Interface: "public0", Addresses: []string{"2602:f5bb::1/64"}, Source: "fe80::1"}
	require.NoError(t, v6.Validate())
	assert.Equal(t, FamilyIPv6, v6.family())

	cases := map[string]func(*GroupConfig){
		"vrid 0":            func(c *GroupConfig) { c.VRID = 0 },
		"no interface":      func(c *GroupConfig) { c.Interface = " " },
		"interval too long": func(c *GroupConfig) { c.AdvertIntervalCentiseconds = 4096 },
		"no addresses":      func(c *GroupConfig) { c.Addresses = nil },
		"bad address":       func(c *GroupConfig) { c.Addresses = []string{"198.18.0.1"} },
		"multicast address": func(c *GroupConfig) { c.Addresses = []string{"224.0.0.18/32"} },
		"mixed families":    func(c *GroupConfig) { c.Addresses = []string{"198.18.0.1/24", "fd00::1/64"} },
		"no source":         func(c *GroupConfig) { c.Source = "" },
		"bad source":        func(c *GroupConfig) { c.Source = "nope" },
		"source family":     func(c *GroupConfig) { c.Source = "fe80::1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := backupConfig()
			mutate(&c)
			var invalid *ErrInvalidGroupConfig
			err := c.Validate()
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Contains(t, err.Error(), "fhrp: group ")
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	cfg := Config{Enabled: true, Groups: []GroupConfig{backupConfig()}}
	require.NoError(t, cfg.Validate())

	dup := Config{Groups: []GroupConfig{backupConfig(), backupConfig()}}
	var d *ErrDuplicateGroup
	require.True(t, errors.As(dup.Validate(), &d))
	assert.Contains(t, dup.Validate().Error(), "configured twice")

	// The same VRID in the other family on the same interface is a
	// different group (different virtual MAC, different multicast group).
	v6 := backupConfig()
	v6.Addresses, v6.Source = []string{"2602:f5bb::1/64"}, "fe80::2"
	require.NoError(t, Config{Groups: []GroupConfig{backupConfig(), v6}}.Validate())

	bad := Config{Groups: []GroupConfig{{}}}
	var invalid *ErrInvalidGroupConfig
	require.True(t, errors.As(bad.Validate(), &invalid))
}

func TestErrors_Messages(t *testing.T) {
	assert.Contains(t, (&ErrTransportRequired{Dependency: "transport"}).Error(), "transport")
	assert.Contains(t, (&ErrGroupNotFound{VRID: 3, Interface: "eth0"}).Error(), "no group 3 on eth0")
	assert.Contains(t, ErrSpeakerNotRunning{}.Error(), "not running")
	assert.Contains(t, ErrSpeakerAlreadyRunning{}.Error(), "already running")
	cause := errors.New("boom")
	tf := &ErrTransportFailed{VRID: 1, Interface: "eth0", Operation: "send", Cause: cause}
	assert.ErrorIs(t, tf, cause)
	assert.Contains(t, tf.Error(), "send")
	ao := &ErrAddressOperationFailed{VRID: 1, Interface: "eth0", Operation: "add", Cause: cause}
	assert.ErrorIs(t, ao, cause)
	assert.Contains(t, ao.Error(), "add")
}
