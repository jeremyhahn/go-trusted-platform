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
	"errors"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// raftSection mirrors the quicbaas keys the App decodes, so the precedence
// is asserted through viper.Unmarshal exactly as platformd loads it.
type raftSection struct {
	QuicBaaS struct {
		RaftAddress       string `mapstructure:"raft-address"`
		RaftListenAddress string `mapstructure:"raft-listen-address"`
	} `mapstructure:"quicbaas"`
}

const raftFile = `
quicbaas:
  raft-address: 10.0.0.1:63000
  raft-listen-address: 10.0.0.1:63001
`

func newRaftViper(t *testing.T, file string) (*viper.Viper, *pflag.FlagSet) {
	t.Helper()
	v := viper.New()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	require.NoError(t, BindRaftAddressFlags(v, flags))
	BindDaemonListenerEnv(v, "PLATFORMD")
	if file != "" {
		v.SetConfigType("yaml")
		require.NoError(t, v.ReadConfig(strings.NewReader(file)))
	}
	return v, flags
}

func decodeRaft(t *testing.T, v *viper.Viper) raftSection {
	t.Helper()
	var s raftSection
	require.NoError(t, v.Unmarshal(&s))
	return s
}

func TestBindRaftAddressFlags_DefaultsEmpty(t *testing.T) {
	v, flags := newRaftViper(t, "")
	s := decodeRaft(t, v)
	assert.Empty(t, s.QuicBaaS.RaftAddress)
	assert.Empty(t, s.QuicBaaS.RaftListenAddress)
	assert.NotNil(t, flags.Lookup("raft-address"))
	assert.NotNil(t, flags.Lookup("raft-listen-address"))
}

func TestBindRaftAddressFlags_FileWhenFlagUnset(t *testing.T) {
	v, _ := newRaftViper(t, raftFile)
	s := decodeRaft(t, v)
	assert.Equal(t, "10.0.0.1:63000", s.QuicBaaS.RaftAddress)
	assert.Equal(t, "10.0.0.1:63001", s.QuicBaaS.RaftListenAddress)
}

func TestBindRaftAddressFlags_EnvOverridesFile(t *testing.T) {
	t.Setenv("PLATFORMD_QUICBAAS_RAFT_ADDRESS", "10.0.0.2:63000")
	t.Setenv("PLATFORMD_QUICBAAS_RAFT_LISTEN_ADDRESS", "0.0.0.0:63000")
	v, _ := newRaftViper(t, raftFile)
	s := decodeRaft(t, v)
	assert.Equal(t, "10.0.0.2:63000", s.QuicBaaS.RaftAddress)
	assert.Equal(t, "0.0.0.0:63000", s.QuicBaaS.RaftListenAddress)
}

func TestBindRaftAddressFlags_FlagOverridesEnv(t *testing.T) {
	t.Setenv("PLATFORMD_QUICBAAS_RAFT_ADDRESS", "10.0.0.2:63000")
	v, flags := newRaftViper(t, raftFile)
	require.NoError(t, flags.Parse([]string{"--raft-address", "10.0.0.3:63000"}))
	s := decodeRaft(t, v)
	assert.Equal(t, "10.0.0.3:63000", s.QuicBaaS.RaftAddress)
	assert.Equal(t, "10.0.0.1:63001", s.QuicBaaS.RaftListenAddress, "an unset flag must not shadow the file")
}

func TestBindRaftAddressFlags_RefusesDuplicateRegistration(t *testing.T) {
	v := viper.New()
	flags := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	require.NoError(t, BindRaftAddressFlags(v, flags))
	err := BindRaftAddressFlags(v, flags)
	var e *ErrFlagAlreadyBound
	require.True(t, errors.As(err, &e), "got %v", err)
	assert.Equal(t, "raft-address", e.Flag)
}
