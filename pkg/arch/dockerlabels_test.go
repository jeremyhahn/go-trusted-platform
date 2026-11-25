package arch

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// exampleMaintainerAddress is the only address a Dockerfile maintainer label
// may carry: the repository is public, and a personal address is an internal
// value (public hygiene, "Internal values are configuration inputs").
const exampleMaintainerAddress = "maintainer@example.com"

// minMaintainerLabels is the number of Dockerfiles under build/docker that
// carry a maintainer label today; fewer means the walk missed them.
const minMaintainerLabels = 9

// TestBuildDockerfilesCarryTheExampleMaintainerAddress requires every
// `LABEL maintainer=` line in a Dockerfile under build/docker to name the
// example address between its angle brackets.
func TestBuildDockerfilesCarryTheExampleMaintainerAddress(t *testing.T) {
	root := repoRoot(t)
	labels := 0
	err := filepath.WalkDir(filepath.Join(root, "build", "docker"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasPrefix(d.Name(), "Dockerfile") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "LABEL maintainer=") {
				continue
			}
			labels++
			open, end := strings.Index(line, "<"), strings.LastIndex(line, ">")
			if open < 0 || end < open || line[open+1:end] != exampleMaintainerAddress {
				t.Errorf("%s:%d: the maintainer label does not carry the address %s between angle brackets",
					rel, i+1, exampleMaintainerAddress)
			}
		}
		return nil
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, labels, minMaintainerLabels, "too few maintainer labels under build/docker")
}
