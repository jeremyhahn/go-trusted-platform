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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportingConfig_NilIsValidAndDefaulted(t *testing.T) {
	var r *ReportingConfig
	require.NoError(t, r.Validate())
	assert.Equal(t, DefaultReportingInterval, r.EffectiveInterval())
	assert.Equal(t, 2*DefaultReportingInterval, r.EffectiveTTL())

	var c *CollectorConfig
	require.NoError(t, c.Validate())
	assert.Equal(t, DefaultReportingPort, c.EffectivePort())
	assert.Equal(t, DefaultReportingTimeout, c.EffectiveTimeout())

	var a *CallerAdmissionConfig
	require.NoError(t, a.Validate())
	assert.Equal(t, CallerStrategyReportingServers, a.EffectiveStrategy())
}

func TestReportingConfig_ValidatesTTLAgainstInterval(t *testing.T) {
	r := &ReportingConfig{Interval: 10 * time.Minute, TTL: 5 * time.Minute}
	err := r.Validate()
	require.Error(t, err)
	var bad ErrInvalidReportingInterval
	require.ErrorAs(t, err, &bad)
	assert.Equal(t, "ttl", bad.Field)

	r = &ReportingConfig{Interval: 10 * time.Minute, TTL: 10 * time.Minute}
	require.NoError(t, r.Validate())
	assert.Equal(t, 10*time.Minute, r.EffectiveTTL())

	r = &ReportingConfig{Interval: 10 * time.Minute}
	require.NoError(t, r.Validate())
	assert.Equal(t, 20*time.Minute, r.EffectiveTTL())
}

func TestReportingConfig_RejectsNegativeDurations(t *testing.T) {
	require.Error(t, (&ReportingConfig{Interval: -time.Second}).Validate())
	require.Error(t, (&ReportingConfig{TTL: -time.Second}).Validate())
	require.Error(t, (&ReportingConfig{Collector: &CollectorConfig{Timeout: -time.Second}}).Validate())
}

func TestCollectorConfig_ValidatesPortAndPCRs(t *testing.T) {
	err := (&CollectorConfig{Port: 70000}).Validate()
	var badPort ErrInvalidCollectorPort
	require.ErrorAs(t, err, &badPort)
	assert.Equal(t, 70000, badPort.Port)
	assert.Contains(t, badPort.Error(), "70000")

	err = (&CollectorConfig{PCRs: []int{0, 24}}).Validate()
	var badPCR ErrInvalidPCR
	require.ErrorAs(t, err, &badPCR)
	assert.Equal(t, 24, badPCR.Index)

	c := &CollectorConfig{Port: 8443, Timeout: 5 * time.Second, PCRs: []int{0, 7}}
	require.NoError(t, c.Validate())
	assert.Equal(t, 8443, c.EffectivePort())
	assert.Equal(t, 5*time.Second, c.EffectiveTimeout())
}

func TestCallerAdmissionConfig_Strategy(t *testing.T) {
	for _, s := range []string{"", "reporting-servers", " Any-Attested ", "allowlist"} {
		c := &CallerAdmissionConfig{Strategy: s}
		require.NoError(t, c.Validate(), s)
	}
	assert.Equal(t, CallerStrategyAnyAttested, (&CallerAdmissionConfig{Strategy: " Any-Attested "}).EffectiveStrategy())

	err := (&CallerAdmissionConfig{Strategy: "anyone"}).Validate()
	var bad ErrInvalidCallerStrategy
	require.ErrorAs(t, err, &bad)
	assert.Equal(t, "anyone", bad.Strategy)
	assert.Contains(t, bad.Error(), "allowlist")
}

func TestAttestation_ValidateIncludesReporting(t *testing.T) {
	a := &Attestation{Reporting: &ReportingConfig{Callers: &CallerAdmissionConfig{Strategy: "nope"}}}
	require.Error(t, a.Validate())
	a.Reporting.Callers.Strategy = CallerStrategyAllowlist
	require.NoError(t, a.Validate())
}
