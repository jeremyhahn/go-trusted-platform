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

package config

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type strictBridge struct {
	Name       string   `yaml:"name" mapstructure:"name"`
	Interfaces []string `yaml:"interfaces" mapstructure:"interfaces"`
}

type StrictCommon struct {
	Tag string `yaml:"tag" mapstructure:"tag"`
}

type strictCustom struct{ v string }

func (c *strictCustom) UnmarshalYAML(n *yaml.Node) error { c.v = n.Value; return nil }

type strictSection struct {
	StrictCommon `yaml:",inline" mapstructure:",squash"`
	Bridges      []strictBridge           `yaml:"bridges" mapstructure:"bridges"`
	Prefix       netip.Prefix             `yaml:"prefix" mapstructure:"prefix"`
	ByName       map[string]*strictBridge `yaml:"by-name" mapstructure:"by-name"`
	Custom       strictCustom             `yaml:"custom" mapstructure:"-"`
	Skipped      string                   `yaml:"-" mapstructure:"-"`
	Plain        int                      `mapstructure:"plain"`
	hidden       string                   //nolint:unused // exercises the unexported-field rule
}

type strictOpen struct {
	Known string         `yaml:"known"`
	Rest  map[string]any `yaml:",inline"`
}

const strictGood = `
other: {anything: goes}
net:
  tag: t
  plain: 3
  prefix: 10.4.1.0/24
  custom: {whatever: 1}
  bridges:
    - name: br-fabric
      interfaces: [bond0]
  by-name:
    a: {name: a}
`

const strictBad = `
net:
  tag: t
  subnets: []
  bridges:
    - name: br-fabric
      members: [bond0]
  by-name:
    a: {name: a, port: 1}
`

// TestCheckYAMLSection accepts a section whose keys all exist, including
// inline, map, slice, self-decoding and absent sections.
func TestCheckYAMLSection(t *testing.T) {
	require.NoError(t, CheckYAMLSection([]byte(strictGood), "net", &strictSection{}))
	require.NoError(t, CheckYAMLSection([]byte(strictGood), "absent", &strictSection{}))
	require.NoError(t, CheckYAMLSection([]byte("known: 1\nfree: 2\n"), "missing", &strictOpen{}))
	require.NoError(t, CheckYAMLSection([]byte("s:\n  known: a\n  free: b\n"), "s", &strictOpen{}), "an inline map accepts any key")
	require.NoError(t, CheckYAMLSection([]byte(""), "net", &strictSection{}))
	require.NoError(t, CheckYAMLSection([]byte("- a\n"), "net", &strictSection{}))
	require.NoError(t, CheckYAMLSection([]byte("net: scalar\n"), "net", &strictSection{}), "shape errors are the decoder's")
	require.NoError(t, CheckYAMLSection([]byte("base: &b {tag: x}\nnet:\n  <<: *b\n  plain: 1\n"), "net", &strictSection{}))
}

// TestCheckYAMLSection_Unknown names every unknown key with its path and
// line.
func TestCheckYAMLSection_Unknown(t *testing.T) {
	err := CheckYAMLSection([]byte(strictBad), "net", &strictSection{})
	var target *ErrUnknownConfigKeys
	require.True(t, errors.As(err, &target), "got %v", err)
	assert.Equal(t, "net", target.Section)
	assert.Equal(t, []UnknownKey{
		{Path: "net.bridges[0].members", Line: 7},
		{Path: "net.by-name.a.port", Line: 9},
		{Path: "net.subnets", Line: 4},
	}, target.Keys)
	assert.Contains(t, err.Error(), "net.bridges[0].members (line 7)")

	err = CheckYAMLSection([]byte("net: [unclosed\n"), "net", &strictSection{})
	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped))
}

func viperOf(t *testing.T, doc string) *viper.Viper {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(doc)))
	return v
}

// TestCheckViperSection decodes a clean section and fills the target.
func TestCheckViperSection(t *testing.T) {
	var s strictSection
	require.NoError(t, CheckViperSection(viperOf(t, "net:\n  tag: t\n  prefix: 10.4.1.0/24\n  bridges: [{name: b, interfaces: [x]}]\n"), "net", &s))
	assert.Equal(t, "t", s.Tag)
	assert.Equal(t, "10.4.1.0/24", s.Prefix.String())
	require.Len(t, s.Bridges, 1)

	require.NoError(t, CheckViperSection(viperOf(t, "other: 1\n"), "net", &strictSection{}))
}

// TestCheckViperSection_Unknown names unknown keys by path, and wraps a
// decode failure.
func TestCheckViperSection_Unknown(t *testing.T) {
	err := CheckViperSection(viperOf(t, strictBad), "net", &strictSection{})
	var target *ErrUnknownConfigKeys
	require.True(t, errors.As(err, &target), "got %v", err)
	paths := make([]string, len(target.Keys))
	for i, k := range target.Keys {
		paths[i] = k.Path
		assert.Zero(t, k.Line, "viper keeps no positions")
	}
	assert.Contains(t, paths, "net.subnets")
	assert.Contains(t, paths, "net.bridges[0].members")
	assert.NotContains(t, err.Error(), "line")

	err = CheckViperSection(viperOf(t, "net:\n  plain: notanumber\n"), "net", &strictSection{})
	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped), "got %v", err)
}
