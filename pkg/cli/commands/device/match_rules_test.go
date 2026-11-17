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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestApplyMatchRuleFlags_NoFlagsKeepsRules(t *testing.T) {
	assert.Nil(t, applyMatchRuleFlags(nil, &matchRuleFlags{}))

	stored := &platformv1.ProfileMatchRules{TpmVendor: "IFX"}
	assert.Same(t, stored, applyMatchRuleFlags(stored, &matchRuleFlags{}))
}

func TestApplyMatchRuleFlags_SetsOnlyGivenRules(t *testing.T) {
	rules := applyMatchRuleFlags(nil, &matchRuleFlags{macPrefix: "52:54:00"})
	require.NotNil(t, rules)
	assert.Equal(t, "52:54:00", rules.GetMacPrefix())
	assert.Empty(t, rules.GetSerialPrefix())

	stored := &platformv1.ProfileMatchRules{MacPrefix: "aa:bb", TpmVendor: "IFX"}
	rules = applyMatchRuleFlags(stored, &matchRuleFlags{serialPrefix: "SN-", model: "r650"})
	assert.Equal(t, "aa:bb", rules.GetMacPrefix())
	assert.Equal(t, "SN-", rules.GetSerialPrefix())
	assert.Equal(t, "r650", rules.GetModel())
	assert.Equal(t, "IFX", rules.GetTpmVendor())
}

func TestBuildMatchRulesOutput(t *testing.T) {
	assert.Nil(t, buildMatchRulesOutput(nil))
	assert.Nil(t, buildMatchRulesOutput(&platformv1.ProfileMatchRules{}))

	output := buildMatchRulesOutput(&platformv1.ProfileMatchRules{MacPrefix: "52:54:00", TpmVendor: "IFX"})
	assert.Equal(t, map[string]interface{}{"mac_prefix": "52:54:00", "tpm_vendor": "IFX"}, output)
}

func TestMatchRulesSummary(t *testing.T) {
	assert.Empty(t, matchRulesSummary(nil))
	assert.Equal(t, "mac_prefix=52:54:00 serial_prefix=SN-",
		matchRulesSummary(&platformv1.ProfileMatchRules{SerialPrefix: "SN-", MacPrefix: "52:54:00"}))
}
