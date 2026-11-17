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

package device

import (
	"strings"

	"github.com/spf13/cobra"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// matchRuleFlags are the match-rule flags the profile and template verbs
// share. A device matches a rule set when its MAC address and serial start
// with the prefixes and its model equals the model (docs/device/cli.md §3.1).
type matchRuleFlags struct {
	macPrefix     string
	serialPrefix  string
	model         string
	modelPattern  string
	serialPattern string
	manufacturer  string
	tpmVendor     string
}

func registerMatchRuleFlags(cmd *cobra.Command, mf *matchRuleFlags) {
	cmd.Flags().StringVar(&mf.macPrefix, "match-mac-prefix", "", "match rule: MAC address prefix (e.g. 52:54:00)")
	cmd.Flags().StringVar(&mf.serialPrefix, "match-serial-prefix", "", "match rule: serial number prefix")
	cmd.Flags().StringVar(&mf.model, "match-model", "", "match rule: exact device model")
	cmd.Flags().StringVar(&mf.modelPattern, "match-model-pattern", "", "match rule: device model, exact match (legacy model_pattern field)")
	cmd.Flags().StringVar(&mf.serialPattern, "match-serial-pattern", "", "match rule: literal serial number prefix (legacy serial_pattern field)")
	cmd.Flags().StringVar(&mf.manufacturer, "match-manufacturer", "", "match rule: device manufacturer")
	cmd.Flags().StringVar(&mf.tpmVendor, "match-tpm-vendor", "", "match rule: TPM vendor (e.g. IFX)")
}

// applyMatchRuleFlags sets each rule whose flag was given on rules, keeping
// the others. It returns rules unchanged (nil included) when no flag was
// given, and allocates a rule set when rules is nil and one was.
func applyMatchRuleFlags(rules *platformv1.ProfileMatchRules, mf *matchRuleFlags) *platformv1.ProfileMatchRules {
	if mf.macPrefix == "" && mf.serialPrefix == "" && mf.model == "" &&
		mf.modelPattern == "" && mf.serialPattern == "" && mf.manufacturer == "" && mf.tpmVendor == "" {
		return rules
	}
	if rules == nil {
		rules = &platformv1.ProfileMatchRules{}
	}
	if mf.macPrefix != "" {
		rules.MacPrefix = mf.macPrefix
	}
	if mf.serialPrefix != "" {
		rules.SerialPrefix = mf.serialPrefix
	}
	if mf.model != "" {
		rules.Model = mf.model
	}
	if mf.modelPattern != "" {
		rules.ModelPattern = mf.modelPattern
	}
	if mf.serialPattern != "" {
		rules.SerialPattern = mf.serialPattern
	}
	if mf.manufacturer != "" {
		rules.ManufacturerMatch = mf.manufacturer
	}
	if mf.tpmVendor != "" {
		rules.TpmVendor = mf.tpmVendor
	}
	return rules
}

// matchRule is one set rule of a rule set, under its output key.
type matchRule struct {
	key   string
	value string
}

// setMatchRules lists the set rules of rules in a fixed order, so the
// table summary does not depend on map iteration.
func setMatchRules(rules *platformv1.ProfileMatchRules) []matchRule {
	all := []matchRule{
		{"mac_prefix", rules.GetMacPrefix()},
		{"serial_prefix", rules.GetSerialPrefix()},
		{"model", rules.GetModel()},
		{"model_pattern", rules.GetModelPattern()},
		{"serial_pattern", rules.GetSerialPattern()},
		{"manufacturer_match", rules.GetManufacturerMatch()},
		{"tpm_vendor", rules.GetTpmVendor()},
	}
	set := make([]matchRule, 0, len(all))
	for _, rule := range all {
		if rule.value != "" {
			set = append(set, rule)
		}
	}
	return set
}

// buildMatchRulesOutput is the match_rules object of the JSON and YAML
// output: one key per set rule, nil when no rule is set.
func buildMatchRulesOutput(rules *platformv1.ProfileMatchRules) map[string]interface{} {
	set := setMatchRules(rules)
	if len(set) == 0 {
		return nil
	}
	output := make(map[string]interface{}, len(set))
	for _, rule := range set {
		output[rule.key] = rule.value
	}
	return output
}

// matchRulesSummary is the table line for a rule set, e.g.
// "mac_prefix=52:54:00 serial_prefix=SN-"; empty when no rule is set.
func matchRulesSummary(rules *platformv1.ProfileMatchRules) string {
	set := setMatchRules(rules)
	parts := make([]string, 0, len(set))
	for _, rule := range set {
		parts = append(parts, rule.key+"="+rule.value)
	}
	return strings.Join(parts, " ")
}
