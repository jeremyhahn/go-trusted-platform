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

	"github.com/spf13/viper"
)

// ErrDecodeYAML reports platform-config YAML that could not be read or decoded
// into its target.
type ErrDecodeYAML struct {
	Cause error
}

func (e ErrDecodeYAML) Error() string {
	return "config: decode platform config: " + e.Cause.Error()
}

func (e ErrDecodeYAML) Unwrap() error {
	return e.Cause
}

// DecodeYAML decodes platform-config YAML bytes into target exactly as
// platformd does: through viper with DecodeHook, so secret references
// (kms://...) land unresolved in secret.SecretValue instead of failing a raw
// yaml decode. It uses a fresh viper instance, never the global one platformd
// owns.
func DecodeYAML(data []byte, target interface{}) error {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return ErrDecodeYAML{Cause: err}
	}
	if err := v.Unmarshal(target, DecodeHook()); err != nil {
		return ErrDecodeYAML{Cause: err}
	}
	return nil
}
