package arch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// failClosedTerms are the conjuncts of the step that stops a pool leg with
// neither the lease nor a LAN registry reference (ruling 862): the artifact
// would cross the WAN and the fallback build is not the image job's image.
var failClosedTerms = []string{
	"steps.lease.outputs.leased != 'true'",
	"needs.integration-image.outputs.image_ref == ''",
	"runner.environment != 'github-hosted'",
	"github.server_url == 'https://github.com'",
}

// integrationFailClosedProblem is why the integration job does not fail a
// pool leg that has no lease and no registry reference before its load step,
// or "".
func integrationFailClosedProblem(data []byte) string {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				If   string `yaml:"if"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return "ci.yml does not parse: " + err.Error()
	}
	job, ok := wf.Jobs["integration"]
	if !ok {
		return "ci.yml has no integration job"
	}
	for _, s := range job.Steps {
		if s.Name == "Load the integration image" {
			return "no step before " + strings.ToLower(s.Name) + " fails a pool leg that has neither the lease nor a LAN registry reference (ruling 862)"
		}
		if poolConjunctsAll(s.If, failClosedTerms) && strings.Contains(s.Run, "exit 1") {
			return ""
		}
	}
	return "the integration job has no load step"
}

// poolConjunctsAll: every term is a top-level conjunct of cond, which holds
// no ||.
func poolConjunctsAll(cond string, terms []string) bool {
	for _, t := range terms {
		if !poolConjunct(cond, t) {
			return false
		}
	}
	return true
}

func TestCIIntegrationFailsClosedOffTheRegistry(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if p := integrationFailClosedProblem(data); p != "" {
		t.Fatal(p)
	}
	body := string(data)
	const stepName = "      - name: No integration image on this pool runner\n"
	i := strings.Index(body, stepName)
	if i < 0 {
		t.Fatalf("ci.yml lacks %q", stepName)
	}
	step := body[i : i+strings.Index(body[i:], "          exit 1\n")+len("          exit 1\n")]
	for _, c := range []struct{ name, old, new string }{
		{"the step removed", step, ""},
		{"a term dropped", " && runner.environment != 'github-hosted' && github.server_url == 'https://github.com'\n        run: |\n          echo \"::error::no lease", " && github.server_url == 'https://github.com'\n        run: |\n          echo \"::error::no lease"},
		{"the job no longer stops", "          exit 1\n\n", "          true\n\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if !strings.Contains(body, c.old) {
				t.Fatalf("ci.yml lacks %q", c.old)
			}
			if p := integrationFailClosedProblem([]byte(strings.Replace(body, c.old, c.new, 1))); p == "" {
				t.Fatal("the mutation passed the check")
			}
		})
	}
}
