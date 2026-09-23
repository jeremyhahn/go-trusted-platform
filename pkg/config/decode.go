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
	"reflect"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/secret"
)

// DecodeHook is the viper decode option every platform configuration loader
// uses, so platformd, a configuration reload and gatewayd decode the same
// YAML the same way:
//
//   - TextUnmarshaler types (netip.Addr, netip.Prefix, custom enums),
//   - durations ("30s") and comma-separated lists,
//   - secret fields (secret.SecretValue — a CA or TPM key password), see
//     StringToSecretValueHookFunc.
func DecodeHook() viper.DecoderConfigOption {
	return viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.TextUnmarshallerHookFunc(),
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
		StringToSecretValueHookFunc,
	))
}

var secretValueType = reflect.TypeOf(secret.SecretValue{})

// StringToSecretValueHookFunc decodes a scalar string into a
// secret.SecretValue field — a literal password or a reference such as
// "kms://ca/root/keys/0/password?ensure=true" — storing it unresolved in Raw.
//
// go-xkms v0.17 holds key passwords as a SecretValue so the plaintext lives in
// a protected enclave, not a Go string. SecretValue decodes from YAML itself,
// but viper decodes through mapstructure, which knows nothing of that and
// refuses a string for a struct; platformd then fails to load a configuration
// with any key password in it. This hook gives mapstructure the behaviour
// SecretValue's YAML decoder already has (go-xkms applies the same hook in its
// own loader). Resolution into the enclave happens afterwards, in
// App.ProcessSecrets, whose secret walker resolves SecretValue fields and
// refuses to start on any it cannot resolve — so a reference never reaches a
// key as its literal password.
func StringToSecretValueHookFunc(from, to reflect.Type, data any) (any, error) {
	if from.Kind() != reflect.String {
		return data, nil
	}
	raw, _ := data.(string)
	switch to {
	case secretValueType:
		return secret.SecretValue{Raw: raw}, nil
	case reflect.PointerTo(secretValueType):
		return &secret.SecretValue{Raw: raw}, nil
	}
	return data, nil
}
