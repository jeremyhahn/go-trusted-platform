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
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// The Raft addresses of the embedded store (#93): the address this node
// advertises to its peers and the address its Raft transport binds. Both
// live in the `quicbaas:` section and are settable by the file, by
// PLATFORMD_QUICBAAS_RAFT_ADDRESS / PLATFORMD_QUICBAAS_RAFT_LISTEN_ADDRESS
// and by --raft-address / --raft-listen-address, under the precedence
// flags > env > file > defaults (conventions/configuration.md §3).
//
// The defaults layer is the App's quicbaas.Config: a single node advertises
// loopback, and a node with join-addresses and no routable advertise
// address is refused by quicbaas.Config.Validate rather than guessed.
const (
	// RaftAddressKey is the viper key of the advertised Raft address.
	RaftAddressKey = "quicbaas.raft-address"
	// RaftListenAddressKey is the viper key of the Raft bind address.
	RaftListenAddressKey = "quicbaas.raft-listen-address"

	raftAddressFlag       = "raft-address"
	raftListenAddressFlag = "raft-listen-address"
)

// BindRaftAddressFlags registers --raft-address and --raft-listen-address on
// flags and binds them to their quicbaas keys on v. A flag the operator did
// not set falls through to the environment and the file; it never shadows
// them. Binding the keys also lets the PLATFORMD_ environment prefix reach
// them (viper only consults the environment for keys it knows).
func BindRaftAddressFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	bindings := []struct {
		flag  string
		key   string
		usage string
	}{
		{raftAddressFlag, RaftAddressKey, "Raft address advertised to peers (config " + RaftAddressKey + ")"},
		{raftListenAddressFlag, RaftListenAddressKey, "Raft transport bind address; empty binds the advertised address (config " + RaftListenAddressKey + ")"},
	}
	for _, b := range bindings {
		if flags.Lookup(b.flag) != nil {
			return &ErrFlagAlreadyBound{Flag: b.flag}
		}
		flags.String(b.flag, "", b.usage)
		if err := v.BindPFlag(b.key, flags.Lookup(b.flag)); err != nil {
			return &WrappedError{Msg: "config: bind " + b.flag, Err: err}
		}
	}
	return nil
}
