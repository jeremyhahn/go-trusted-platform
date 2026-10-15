package bootstrap

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// shippedTemplateRoot is the tree of role templates the platform ships.
const shippedTemplateRoot = "../../configs/platform/templates"

// controlPlaneIssuedChallenge is the ACME challenge through which a node takes
// its platform listener's certificate from the control-plane CA.
const controlPlaneIssuedChallenge = "device-attest-01"

// shippedTemplateRoles classifies every file name under shippedTemplateRoot by
// the bootstrap role it configures. The empty role marks a file that is not a
// gateway or worker template: control-plane.yaml and the single-node
// default.yaml are their own CA, gatewayd.yaml configures gatewayd, not
// platformd, and desk-overrides.yaml merges onto a control-plane template. A
// file name missing here fails the test, so a new role template cannot ship
// unchecked.
var shippedTemplateRoles = map[string]string{
	"gateway.yaml":        RoleGateway,
	"compute.yaml":        RoleWorker,
	"control-plane.yaml":  "",
	"default.yaml":        "",
	"gatewayd.yaml":       "",
	"desk-overrides.yaml": "",
}

type shippedNodeTemplate struct {
	name string // path relative to shippedTemplateRoot
	path string
	role string
}

// shippedNodeTemplates returns every shipped gateway and worker template.
func shippedNodeTemplates(t *testing.T) []shippedNodeTemplate {
	t.Helper()
	var templates []shippedNodeTemplate
	err := filepath.WalkDir(shippedTemplateRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		role, known := shippedTemplateRoles[d.Name()]
		if !known {
			t.Errorf("%s: unclassified template; add it to shippedTemplateRoles", path)
			return nil
		}
		if role == "" {
			return nil
		}
		name, err := filepath.Rel(shippedTemplateRoot, path)
		if err != nil {
			return err
		}
		templates = append(templates, shippedNodeTemplate{name: name, path: path, role: role})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", shippedTemplateRoot, err)
	}
	return templates
}

// platformListenerChallenge returns the certificate.acme.challenge of the
// tls-port listener in mergedYAML, from the webservices list or the singular
// webservice block, and "" when the listener declares none.
func platformListenerChallenge(mergedYAML string, tlsPort int) (string, error) {
	type listener struct {
		TLSPort     int `yaml:"tls-port"`
		Certificate struct {
			ACME struct {
				Challenge string `yaml:"challenge"`
			} `yaml:"acme"`
		} `yaml:"certificate"`
	}
	var cfg struct {
		Webservices []listener `yaml:"webservices"`
		Webservice  *listener  `yaml:"webservice"`
	}
	if err := yaml.Unmarshal([]byte(mergedYAML), &cfg); err != nil {
		return "", err
	}
	if cfg.Webservice != nil {
		cfg.Webservices = append(cfg.Webservices, *cfg.Webservice)
	}
	for _, ws := range cfg.Webservices {
		if ws.TLSPort == tlsPort {
			return ws.Certificate.ACME.Challenge, nil
		}
	}
	return "", nil
}

// Every shipped gateway and worker template must give the post-install health
// probe a name to verify the platform listener by, and must take that
// listener's certificate from the control-plane CA: the probe verifies against
// the platform anchor, so a leaf from the node's own CA fails it (#655).
func TestShippedNodeTemplates_PlatformListenerIsIssuedByTheControlPlane(t *testing.T) {
	templates := shippedNodeTemplates(t)
	if len(templates) == 0 {
		t.Fatalf("no gateway or worker templates found under %s", shippedTemplateRoot)
	}
	for _, tmpl := range templates {
		t.Run(tmpl.name, func(t *testing.T) {
			o := newTrustTestOrchestrator()
			o.config.Templates = map[string]string{tmpl.role: tmpl.path}
			node := &DiscoveredNode{NodeConfig: NodeConfig{Hostname: "node-01", Role: tmpl.role}}

			name, err := o.nodeTLSName(node)
			if err != nil {
				t.Fatalf("the platform listener must declare a TLS name: %v", err)
			}
			if name == "" {
				t.Fatal("nodeTLSName returned an empty name without an error")
			}

			merged, err := o.resolveNodeConfig(node.Hostname, node.Role, nil)
			if err != nil {
				t.Fatalf("resolve template: %v", err)
			}
			challenge, err := platformListenerChallenge(merged, nodeWebserviceTLSPort)
			if err != nil {
				t.Fatalf("parse merged template: %v", err)
			}
			if challenge != controlPlaneIssuedChallenge {
				t.Errorf("the tls-port %d listener (%s) must set certificate.acme.challenge: %s, got %q",
					nodeWebserviceTLSPort, name, controlPlaneIssuedChallenge, challenge)
			}
		})
	}
}

func TestPlatformListenerChallenge(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "webservices list",
			yaml: "webservices:\n  - tls-port: 443\n    certificate:\n      acme:\n        challenge: http-01\n" +
				"  - tls-port: 9443\n    certificate:\n      acme:\n        challenge: device-attest-01\n",
			want: "device-attest-01",
		},
		{
			name: "singular webservice",
			yaml: "webservice:\n  tls-port: 9443\n  certificate:\n    acme:\n      challenge: device-attest-01\n",
			want: "device-attest-01",
		},
		{
			name: "listener without acme",
			yaml: "webservice:\n  tls-port: 9443\n  certificate:\n    subject:\n      cn: w1.example.test\n",
			want: "",
		},
		{
			name: "no platform listener",
			yaml: "webservices:\n  - tls-port: 443\n    certificate:\n      acme:\n        challenge: http-01\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := platformListenerChallenge(tc.yaml, nodeWebserviceTLSPort)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("challenge = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPlatformListenerChallenge_InvalidYAML(t *testing.T) {
	if _, err := platformListenerChallenge("webservices: [unterminated", nodeWebserviceTLSPort); err == nil {
		t.Fatal("malformed YAML must be reported, not read as a listener without a challenge")
	}
}
