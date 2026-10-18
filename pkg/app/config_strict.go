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

package app

import (
	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
)

// strictSection is one platform-config section whose unknown keys are
// errors, with a constructor for a fresh value of its Go type.
type strictSection struct {
	name   string
	target func() any
}

// strictSections are the sections checked for unknown keys on every loader
// path. Pre-release, a key the schema no longer has (sdn.networks,
// sdn.transit, network.subnets …) must fail the load, not be ignored.
var strictSections = []strictSection{
	{name: "network", target: func() any { return &installer.NetworkConfig{} }},
	{name: "sdn", target: func() any { return &sdn.Config{} }},
	{name: "pxe", target: func() any { return &pxe.Config{} }},
}

// CheckPlatformConfigViper refuses unknown keys in the strictly checked
// sections of the configuration v holds (platformd's viper load path).
func CheckPlatformConfigViper(v *viper.Viper) error {
	for _, s := range strictSections {
		if err := config.CheckViperSection(v, s.name, s.target()); err != nil {
			return err
		}
	}
	return nil
}

// CheckPlatformConfigYAML refuses unknown keys, with their lines, in the
// strictly checked sections of a platform config document (the yaml
// loaders of platformctl install and diskimage assemble).
func CheckPlatformConfigYAML(doc []byte) error {
	for _, s := range strictSections {
		if err := config.CheckYAMLSection(doc, s.name, s.target()); err != nil {
			return err
		}
	}
	return nil
}
