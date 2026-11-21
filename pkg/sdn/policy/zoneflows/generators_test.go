package zoneflows_test

import (
	"strconv"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// TestQuarantine_CookiesAreNumeric checks every quarantine rule's cookie is
// a decimal or hex uint64: the OpenFlow encoder rejects anything else and
// fails the whole quarantine batch (#1694).
func TestQuarantine_CookiesAreNumeric(t *testing.T) {
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{})
	var cookies int
	for _, r := range gs.Generate("7", zone.ZoneQuarantine, zoneflows.Untagged(100)) {
		if r.Cookie == "" {
			continue
		}
		cookies++
		if _, err := strconv.ParseUint(r.Cookie, 0, 64); err != nil {
			t.Errorf("cookie %q of rule %q is not a uint64: %v", r.Cookie, r.Match, err)
		}
	}
	if cookies == 0 {
		t.Fatal("the quarantine default drop carries no cookie")
	}
}
