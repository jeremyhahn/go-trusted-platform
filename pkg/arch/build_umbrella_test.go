package arch

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The cloud umbrellas WITH_AWS, WITH_GCP and WITH_AZURE follow the handbook
// convention software/conventions/build-tags.md (owner ruling 683 (1)):
// unset by default, 1 turns every service toggle of the provider on, 0 forces
// every one off over the individual toggles, and left unset the individual
// toggles decide.

// cloudUmbrella names a provider umbrella, its service toggles and the build
// tag each toggle adds in the Makefile's BUILD_TAGS construction.
type cloudUmbrella struct {
	umbrella string
	toggles  []string
	tags     []string
}

var cloudUmbrellas = []cloudUmbrella{
	{
		umbrella: "WITH_AWS",
		toggles:  []string{"WITH_AWS_KMS", "WITH_OBJSTORE_S3", "WITH_AWS_COMPUTE"},
		tags:     []string{"awskms", "awss3", "awscompute"},
	},
	{
		umbrella: "WITH_GCP",
		toggles:  []string{"WITH_GCP_KMS", "WITH_OBJSTORE_GCS", "WITH_GCP_COMPUTE"},
		tags:     []string{"gcpkms", "gcpstorage", "gcpcompute"},
	},
	{
		umbrella: "WITH_AZURE",
		toggles:  []string{"WITH_AZURE_KV", "WITH_OBJSTORE_AZURE", "WITH_AZURE_COMPUTE"},
		tags:     []string{"azurekv", "azureblob", "azurecompute"},
	},
}

// printBuildTags runs `make print-build-tags` at the repository root with the
// given variables on the command line and returns the tag list. The variables
// of the calling environment that the Makefile's tag list reads (every WITH_*
// toggle and GO_BUILD_TAGS, which the Makefile appends to every result) are
// dropped, as are MAKEFLAGS, MAKEOVERRIDES and MFLAGS, which carry a parent
// make's command-line variables; GO_BUILD_TAGS= is also passed empty on the
// command line, before the case's own variables, so the list measures only the
// toggles the case sets.
func printBuildTags(t *testing.T, vars ...string) []string {
	t.Helper()
	args := append([]string{"-s", "--no-print-directory", "print-build-tags", "GO_BUILD_TAGS="}, vars...)
	cmd := exec.Command("make", args...)
	cmd.Dir = repoRoot(t)
	for _, kv := range os.Environ() {
		if !inheritedTagVar(kv) {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, err := cmd.Output()
	require.NoError(t, err, "make print-build-tags %v", vars)
	return strings.Fields(string(out))
}

// inheritedTagVar reports whether the environment entry kv is one that would
// change `make print-build-tags` behind the test's back.
func inheritedTagVar(kv string) bool {
	if strings.HasPrefix(kv, "WITH_") {
		return true
	}
	for _, name := range []string{"GO_BUILD_TAGS=", "MAKEFLAGS=", "MAKEOVERRIDES=", "MFLAGS="} {
		if strings.HasPrefix(kv, name) {
			return true
		}
	}
	return false
}

func TestBuildUmbrellaCloudProviders(t *testing.T) {
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("make is not on PATH")
	}

	defaults := printBuildTags(t)
	for _, base := range []string{"iam", "rest", "quic", "mcp", "cluster", "gms_pure_go", "opa"} {
		require.Contains(t, defaults, base, "default build")
	}
	for _, p := range cloudUmbrellas {
		for _, tag := range p.tags {
			require.NotContains(t, defaults, tag, "default build has no cloud provider tag")
		}
	}

	t.Run("inherited GO_BUILD_TAGS", func(t *testing.T) {
		t.Setenv("GO_BUILD_TAGS", "awscompute")
		got := printBuildTags(t)
		require.NotContains(t, got, "awscompute", "an inherited GO_BUILD_TAGS does not reach the defaults")
		require.Equal(t, defaults, got)
	})

	for _, p := range cloudUmbrellas {
		t.Run(p.umbrella+"=1", func(t *testing.T) {
			got := printBuildTags(t, p.umbrella+"=1")
			for _, tag := range p.tags {
				require.Contains(t, got, tag)
			}
			var rest []string
			for _, tag := range got {
				if !slices.Contains(p.tags, tag) {
					rest = append(rest, tag)
				}
			}
			require.Subset(t, defaults, rest, "%s=1 adds only the provider's tags", p.umbrella)
		})

		t.Run(p.umbrella+"=0 over toggles", func(t *testing.T) {
			vars := []string{p.umbrella + "=0"}
			for _, toggle := range p.toggles {
				vars = append(vars, toggle+"=1")
			}
			got := printBuildTags(t, vars...)
			for _, tag := range p.tags {
				require.NotContains(t, got, tag, "%s=0 forces the provider's services off", p.umbrella)
			}
		})

		t.Run(p.umbrella+"=1 over toggles=0", func(t *testing.T) {
			vars := []string{p.umbrella + "=1"}
			for _, toggle := range p.toggles {
				vars = append(vars, toggle+"=0")
			}
			got := printBuildTags(t, vars...)
			for _, tag := range p.tags {
				require.Contains(t, got, tag, "%s=1 forces the provider's services on", p.umbrella)
			}
		})

		t.Run(p.umbrella+"=0 "+p.toggles[0]+"=1", func(t *testing.T) {
			got := printBuildTags(t, p.umbrella+"=0", p.toggles[0]+"=1")
			for _, tag := range p.tags {
				require.NotContains(t, got, tag, "%s=0 overrides %s=1", p.umbrella, p.toggles[0])
			}
		})

		t.Run(p.toggles[0]+"=1 alone", func(t *testing.T) {
			got := printBuildTags(t, p.toggles[0]+"=1")
			require.Contains(t, got, p.tags[0])
			for _, tag := range p.tags[1:] {
				require.NotContains(t, got, tag, "unset umbrella leaves the other toggles alone")
			}
		})
	}
}
