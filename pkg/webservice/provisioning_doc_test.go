package webservice

import (
	"os"
	"strings"
	"testing"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// webUserDoc is the operator guide whose provisioning listener example an
// operator copies into platformd's configuration.
const webUserDoc = "../../docs/web/user.md"

// documentedProvisioningListener returns the provisioning listener from the
// first YAML example in the doc that declares one.
func documentedProvisioningListener(t *testing.T, doc string) *v1.Config {
	t.Helper()
	blocks := strings.Split(doc, "```yaml\n")
	for _, block := range blocks[1:] {
		body, _, closed := strings.Cut(block, "```")
		require.True(t, closed, "unterminated yaml block in %s", webUserDoc)
		if !strings.Contains(body, "surface: provisioning") {
			continue
		}
		var section struct {
			WebServices []*v1.Config `yaml:"webservices"`
		}
		require.NoError(t, yaml.Unmarshal([]byte(body), &section))
		for _, ws := range section.WebServices {
			if ws != nil && ws.Surface == v1.SurfaceProvisioning {
				return ws
			}
		}
	}
	require.FailNow(t, "no provisioning listener example", "in %s", webUserDoc)
	return nil
}

// The documented listener must be one platformd can start: it has a TLS key
// and a certificate identity, and it passes the provisioning validation.
// Codex review 4948 found an example with neither, which crashed platformd.
func TestProvisioningSurface_DocumentedExampleLoads(t *testing.T) {
	doc, err := os.ReadFile(webUserDoc)
	require.NoError(t, err)

	ws := documentedProvisioningListener(t, string(doc))

	require.NotNil(t, ws.Key, "the example has no key")
	attrs, err := ws.Key.ToKeyAttributes()
	require.NoError(t, err)
	assert.NotZero(t, attrs.KeyAlgorithm)
	assert.NotNil(t, attrs.Password, "the key has no password reference")
	assert.NotEmpty(t, ws.Certificate.Subject.CommonName, "the certificate has no CN")
	assert.NoError(t, ValidateProvisioningSurface(ws, testPlan(t)))
}
