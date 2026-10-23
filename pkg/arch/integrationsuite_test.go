// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package arch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// integrationRunner is the devcontainer runner script every integration
	// suite goes through.
	integrationRunner = "run-integration-tests.sh"

	// integrationSuiteDefine is the canned recipe that owns the single
	// `docker run` invocation of integrationRunner.
	integrationSuiteDefine = "run-integration-suite"
)

// integrationSuiteRequiredFlags are the docker arguments the shared define
// must carry. Without the module-cache mount the container resolves every
// dependency over the network, and without GOWORK=off the build honours a
// host go.work the container does not have; together they stopped
// `make integration-test-sdn` before it reached a test (#539).
var integrationSuiteRequiredFlags = []string{
	"-v $(GO_MODULE_CACHE):/go/pkg/mod",
	"-e GOWORK=off",
}

// IntegrationSuiteError reports one Makefile line that lets an integration
// suite run without the shared devcontainer block: a recipe that invokes the
// runner script itself, or a shared define that lost a required flag.
type IntegrationSuiteError struct {
	// Line is the 1-based Makefile line of the finding.
	Line int

	// Target is the rule whose recipe contains the line, or "(top level)".
	Target string

	// Reason says what is wrong on that line.
	Reason string
}

// Error renders the finding as a clickable `Makefile:<line>` reference.
func (e *IntegrationSuiteError) Error() string {
	return fmt.Sprintf("Makefile:%d (%s): %s", e.Line, e.Target, e.Reason)
}

// scanIntegrationSuites returns every place in makefile where an integration
// suite can bypass the shared define, and every required flag the define is
// missing. A makefile with no define at all is itself a finding.
func scanIntegrationSuites(makefile string) []*IntegrationSuiteError {
	var findings []*IntegrationSuiteError
	defineLine := 0
	inDefine := false
	var defineText strings.Builder

	for _, line := range splitMakeLogicalLines(makefile) {
		trimmed := strings.TrimSpace(line.Text)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			continue
		case trimmed == "define "+integrationSuiteDefine:
			inDefine = true
			defineLine = line.Start
			continue
		case inDefine && trimmed == "endef":
			inDefine = false
			continue
		}
		if inDefine {
			defineText.WriteString(line.Text)
			defineText.WriteString("\n")
			continue
		}
		if strings.Contains(line.Text, integrationRunner) {
			findings = append(findings, &IntegrationSuiteError{
				Line:   line.Start,
				Target: line.Target,
				Reason: fmt.Sprintf("invokes %s directly; use $(call %s,<keyword>) instead",
					integrationRunner, integrationSuiteDefine),
			})
		}
	}

	if defineLine == 0 {
		return append(findings, &IntegrationSuiteError{
			Line:   0,
			Target: "(top level)",
			Reason: fmt.Sprintf("the %s define is missing", integrationSuiteDefine),
		})
	}
	for _, flag := range integrationSuiteRequiredFlags {
		if !strings.Contains(defineText.String(), flag) {
			findings = append(findings, &IntegrationSuiteError{
				Line:   defineLine,
				Target: integrationSuiteDefine,
				Reason: fmt.Sprintf("the define does not pass %q to docker run", flag),
			})
		}
	}
	return findings
}

// TestMakefileIntegrationSuitesUseSharedDefine guards #539: every integration
// target, including the all-suites `integration-test`, reaches the runner
// only through the shared define, so none can drift off its module cache and
// GOWORK=off again.
func TestMakefileIntegrationSuitesUseSharedDefine(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	require.NoError(t, err)

	var lines []string
	for _, f := range scanIntegrationSuites(string(data)) {
		lines = append(lines, f.Error())
	}
	require.Empty(t, lines,
		"these Makefile recipes run an integration suite without the shared "+
			"devcontainer block. Replace the hand-written docker run with "+
			"$(call run-integration-suite,<keyword>):\n%s", strings.Join(lines, "\n"))
}

func TestScanIntegrationSuitesFindsBypass(t *testing.T) {
	makefile := strings.Join([]string{
		"define run-integration-suite",
		"\t@docker run --rm \\",
		"\t\t-v $(GO_MODULE_CACHE):/go/pkg/mod \\",
		"\t\t-e GOWORK=off \\",
		"\t\timage bash /workspace/run-integration-tests.sh $(1)",
		"endef",
		"",
		"integration-test-good: build-devcontainer",
		"\t$(call run-integration-suite,good)",
		"",
		"integration-test-bad: build-devcontainer",
		"\t@docker run --rm \\",
		"\t\timage \\",
		"\t\tbash /workspace/run-integration-tests.sh bad",
	}, "\n")

	findings := scanIntegrationSuites(makefile)
	require.Len(t, findings, 1)
	require.Equal(t, 12, findings[0].Line)
	require.Equal(t, "integration-test-bad", findings[0].Target)
	require.Contains(t, findings[0].Error(), "Makefile:12 (integration-test-bad)")
}

func TestScanIntegrationSuitesFindsMissingFlags(t *testing.T) {
	makefile := strings.Join([]string{
		"VAR := 1",
		"define run-integration-suite",
		"\t@docker run --rm image bash /workspace/run-integration-tests.sh $(1)",
		"endef",
	}, "\n")

	findings := scanIntegrationSuites(makefile)
	require.Len(t, findings, 2)
	for _, f := range findings {
		require.Equal(t, 2, f.Line)
		require.Equal(t, "run-integration-suite", f.Target)
	}
	require.Contains(t, findings[0].Reason, "GO_MODULE_CACHE")
	require.Contains(t, findings[1].Reason, "GOWORK=off")
}

func TestScanIntegrationSuitesRejectsInvalidInput(t *testing.T) {
	findings := scanIntegrationSuites("")
	require.Len(t, findings, 1, "a Makefile without the shared define is a finding")
	require.Contains(t, findings[0].Reason, "define is missing")

	findings = scanIntegrationSuites("# run-integration-tests.sh in a comment\n")
	require.Len(t, findings, 1, "a comment naming the runner is not a bypass")
	require.Contains(t, findings[0].Reason, "define is missing")
}
