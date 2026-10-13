package arch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Makefile builds every pinned Go tool from its own tools module under
// build/tools-src, with `go build -C <module> -mod=readonly`, never with
// `go install <pkg>@<version>` (#584). The @version form makes the go command
// look up the module's deprecation notice, a module query that a lane's
// GOPROXY=off refuses even when every module is already in the cache, so
// `make lint` could not build its linters in a lane. A build from a module
// with a committed go.sum makes no query.
//
// `@latest` installs are not pins (devops.md §9 tools take @latest by design)
// and are out of scope; comment lines are prose, not recipes.

// PinnedGoInstallError reports a Makefile line that installs a Go tool at a
// pinned version with `go install`.
type PinnedGoInstallError struct {
	// Line is the 1-based line in the Makefile.
	Line int

	// Package is the Go package path being installed.
	Package string

	// Version is the version after the @, as written (it may be a make variable).
	Version string
}

func (e *PinnedGoInstallError) Error() string {
	return fmt.Sprintf("Makefile:%d: go install %s@%s: build a pinned tool from a tools module "+
		"under build/tools-src with `go build -C <module> -mod=readonly` instead; the @version "+
		"form needs a module query that GOPROXY=off refuses (#584)", e.Line, e.Package, e.Version)
}

// pinnedGoInstalls returns every pinned `go install <pkg>@<version>` in a
// Makefile's text, in line order.
func pinnedGoInstalls(makefile string) []*PinnedGoInstallError {
	var findings []*PinnedGoInstallError
	for i, line := range strings.Split(makefile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, m := range goInstallRe.FindAllStringSubmatch(line, -1) {
			if strings.HasPrefix(m[2], "latest") {
				continue
			}
			findings = append(findings, &PinnedGoInstallError{Line: i + 1, Package: m[1], Version: m[2]})
		}
	}
	return findings
}

func TestMakefileBuildsPinnedToolsFromToolsModules(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	require.NoError(t, err)

	for _, finding := range pinnedGoInstalls(string(data)) {
		t.Error(finding)
	}
}

const fixturePinnedInstalls = `# go install example.com/prose/cmd/x@v1.0.0 in a comment is not a recipe
$(LINTER):
	@GOBIN=$(abspath $(DIR)) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	@go build -C $(SRC) -mod=readonly -o $(abspath $(LINTER)) github.com/rhysd/actionlint/cmd/actionlint
install-vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest; \
	echo "Install with: go install github.com/wadey/gocovmerge@latest$(RESET)"; \
	go install -trimpath honnef.co/go/tools/cmd/staticcheck@v0.8.1
`

func TestPinnedGoInstallsFindsEachPin(t *testing.T) {
	findings := pinnedGoInstalls(fixturePinnedInstalls)
	require.Len(t, findings, 2)

	require.Equal(t, 3, findings[0].Line)
	require.Equal(t, "github.com/golangci/golangci-lint/v2/cmd/golangci-lint", findings[0].Package)
	require.Equal(t, "$(GOLANGCI_LINT_VERSION)", findings[0].Version)
	require.Contains(t, findings[0].Error(), "Makefile:3:")
	require.Contains(t, findings[0].Error(), "GOPROXY=off")

	require.Equal(t, 8, findings[1].Line, "a flag between install and the package is still a pin")
	require.Equal(t, "honnef.co/go/tools/cmd/staticcheck", findings[1].Package)
	require.Equal(t, "v0.8.1", findings[1].Version)
}

func TestPinnedGoInstallsAcceptsBuildsLatestAndComments(t *testing.T) {
	text := strings.Join([]string{
		"# go install example.com/cmd/x@v1.0.0",
		"\t@go build -C build/tools-src/gosec -o $(abspath $(GOSEC)) github.com/securego/gosec/v2/cmd/gosec",
		"\tgo install github.com/wadey/gocovmerge@latest",
		"",
	}, "\n")

	require.Empty(t, pinnedGoInstalls(text))
	require.Empty(t, pinnedGoInstalls(""))
}
