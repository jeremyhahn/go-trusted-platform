package arch

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// featureTableRunner is the suite runner holding the project's one
// integration feature table, TARGET_PACKAGES.
const featureTableRunner = "build/docker/devcontainer/run-integration-tests.sh"

// featureTableRow is one `[key]="patterns"` row of the table.
var featureTableRow = regexp.MustCompile(`^\[([A-Za-z0-9_.-]+)\]="([^"]*)"`)

// parseFeatureTable returns the TARGET_PACKAGES rows of the runner script,
// key to patterns, without `all` (the runner's keyword for everything).
func parseFeatureTable(script string) map[string][]string {
	table := map[string][]string{}
	_, body, found := strings.Cut(script, "\ndeclare -A TARGET_PACKAGES=(\n")
	if !found {
		return table
	}
	body, _, _ = strings.Cut(body, "\n)")
	for _, line := range strings.Split(body, "\n") {
		m := featureTableRow.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[1] == "all" {
			continue
		}
		table[m[1]] = strings.Fields(m[2])
	}
	return table
}

// featurePatternCovers: a pattern ending /... covers its directory and
// everything under it; any other pattern is that one package. dir is
// slash-separated and relative to the repository root.
func featurePatternCovers(pattern, dir string) bool {
	p := strings.TrimPrefix(pattern, "./")
	if prefix, ok := strings.CutSuffix(p, "/..."); ok {
		return dir == prefix || strings.HasPrefix(dir, prefix+"/")
	}
	return dir == strings.TrimSuffix(p, "/")
}

// featureTableFindings is the handbook testing-guidelines.md section 4
// check (ruling 1171): one finding per feature with no
// `integration-test-<key>:` target in the makefile, and one per integration
// test directory no feature's pattern covers.
func featureTableFindings(table map[string][]string, makefile string, testDirs []string) []string {
	var findings []string
	keys := make([]string, 0, len(table))
	for key := range table {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if key == "all" {
			continue
		}
		target := regexp.MustCompile(`(?m)^integration-test-` + regexp.QuoteMeta(key) + `:`)
		if !target.MatchString(makefile) {
			findings = append(findings, fmt.Sprintf("feature %q has no integration-test-%s target in the Makefile", key, key))
		}
	}
	for _, dir := range testDirs {
		covered := false
		for _, key := range keys {
			if key == "all" {
				continue
			}
			for _, pattern := range table[key] {
				if featurePatternCovers(pattern, dir) {
					covered = true
				}
			}
		}
		if !covered {
			findings = append(findings, fmt.Sprintf("integration test directory %s is in no feature of TARGET_PACKAGES", dir))
		}
	}
	return findings
}

func TestFeatureTableFindingsCleanTable(t *testing.T) {
	table := parseFeatureTable("x\ndeclare -A TARGET_PACKAGES=(\n" +
		"    [all]=\"\"\n" +
		"    [alpha]=\"./test/integration/alpha/...\"\n" +
		"    [beta]=\"./test/integration/beta/ ./test/integration/beta/mock/...\"\n" +
		"    [root]=\"./test/integration\"\n" +
		")\ndeclare -A LATER=(\n    [gamma]=\"./test/integration/gamma/...\"\n)\n")
	require.Equal(t, map[string][]string{
		"alpha": {"./test/integration/alpha/..."},
		"beta":  {"./test/integration/beta/", "./test/integration/beta/mock/..."},
		"root":  {"./test/integration"},
	}, table)
	makefile := "integration-test-alpha: build-devcontainer\n\t$(call run-integration-suite,alpha)\n" +
		"integration-test-beta: build-devcontainer\n" +
		"integration-test-root: build-devcontainer\n"
	dirs := []string{"test/integration", "test/integration/alpha", "test/integration/alpha/sub",
		"test/integration/beta", "test/integration/beta/mock/deep"}
	require.Empty(t, featureTableFindings(table, makefile, dirs))
}

func TestFeatureTableFindingsFeatureWithoutTarget(t *testing.T) {
	table := map[string][]string{"alpha": {"./test/integration/alpha/..."}, "alpha-vm": {"./test/integration/alpha/..."}}
	// A comment or a longer target name is not the feature's target.
	makefile := "integration-test-alpha: x\n## integration-test-alpha-vm: y\nintegration-test-alpha-vm-extra: z\n"
	require.Equal(t, []string{`feature "alpha-vm" has no integration-test-alpha-vm target in the Makefile`},
		featureTableFindings(table, makefile, []string{"test/integration/alpha"}))
}

func TestFeatureTableFindingsTestDirInNoFeature(t *testing.T) {
	table := map[string][]string{"disk": {"./test/integration/disk"}, "net": {"./test/integration/net/"}}
	makefile := "integration-test-disk: x\nintegration-test-net: x\n"
	// A pattern without /... is that one package, not its subdirectories.
	require.Equal(t, []string{
		"integration test directory test/integration/disk/userspace is in no feature of TARGET_PACKAGES",
		"integration test directory test/integration/net/topology is in no feature of TARGET_PACKAGES",
	}, featureTableFindings(table, makefile, []string{
		"test/integration/disk", "test/integration/disk/userspace", "test/integration/net", "test/integration/net/topology",
	}))
}

// TestIntegrationFeatureTableMatchesTargetsAndTests: handbook
// testing-guidelines.md section 4, ruling 1171. Every integration test
// directory belongs to a feature of the one table, and every feature of the
// table has its make integration-test-<feature> target.
func TestIntegrationFeatureTableMatchesTargetsAndTests(t *testing.T) {
	root := repoRoot(t)
	script, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(featureTableRunner)))
	require.NoError(t, err)
	table := parseFeatureTable(string(script))
	require.NotEmpty(t, table, "no TARGET_PACKAGES rows in %s", featureTableRunner)
	makefile, err := os.ReadFile(filepath.Join(root, "Makefile"))
	require.NoError(t, err)

	seen := map[string]bool{}
	var dirs []string
	err = filepath.WalkDir(filepath.Join(root, "test", "integration"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}
		if rel = filepath.ToSlash(rel); !seen[rel] {
			seen[rel] = true
			dirs = append(dirs, rel)
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, dirs)

	findings := featureTableFindings(table, string(makefile), dirs)
	require.Empty(t, findings,
		"the integration feature table (TARGET_PACKAGES in %s), the Makefile and test/integration disagree. "+
			"Add a row for each test directory and an integration-test-<feature> target for each row:\n%s",
		featureTableRunner, strings.Join(findings, "\n"))
}
