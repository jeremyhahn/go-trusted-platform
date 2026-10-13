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
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// daemonConfigurationDoc is the operator reference for the `daemon:`
// section. Handbook 00 L9: a key written there must be one platformd
// decodes (#565).
const daemonConfigurationDoc = "../../docs/daemon/configuration.md"

// daemonConfigDocs are the daemon documents that show platformd
// configuration. cli.md is absent on purpose: its yaml is platformctl's own
// context file.
var daemonConfigDocs = []string{
	daemonConfigurationDoc,
	"../../docs/daemon/README.md",
	"../../docs/daemon/api-reference-mcp.md",
	"../../docs/daemon/api-reference-rest.md",
	"../../docs/daemon/api-reference-unix.md",
}

var yamlFence = regexp.MustCompile("(?s)```yaml\n(.*?)```")

// undecodedDaemonKeys returns, sorted, every key the markdown's yaml blocks
// write that the daemon decoder does not know: a top-level key other than
// `daemon`, or a leaf under `daemon:` that is not one of v's keys.
func undecodedDaemonKeys(markdown []byte, v *viper.Viper) ([]string, error) {
	known := v.AllKeys()
	var undecoded []string
	for _, match := range yamlFence.FindAllSubmatch(markdown, -1) {
		var block map[string]any
		if err := yaml.Unmarshal(match[1], &block); err != nil {
			return nil, err
		}
		for key, value := range block {
			if key != daemonKeyPrefix {
				undecoded = append(undecoded, key)
				continue
			}
			for _, leaf := range yamlLeafKeys(key, value) {
				if !slices.Contains(known, leaf) {
					undecoded = append(undecoded, leaf)
				}
			}
		}
	}
	slices.Sort(undecoded)
	return slices.Compact(undecoded), nil
}

// yamlLeafKeys flattens a decoded yaml value into dotted leaf keys.
func yamlLeafKeys(prefix string, value any) []string {
	children, ok := value.(map[string]any)
	if !ok {
		return []string{prefix}
	}
	var leaves []string
	for key, child := range children {
		leaves = append(leaves, yamlLeafKeys(prefix+"."+key, child)...)
	}
	return leaves
}

func TestDaemonConfigDocs_DocumentOnlyDecodedKeys(t *testing.T) {
	v, _ := newDaemonViper(t)
	for _, doc := range daemonConfigDocs {
		t.Run(filepath.Base(doc), func(t *testing.T) {
			markdown, err := os.ReadFile(doc)
			require.NoError(t, err)
			if doc == daemonConfigurationDoc {
				require.Regexp(t, yamlFence, string(markdown),
					"the reference must show the daemon section it documents")
			}

			undecoded, err := undecodedDaemonKeys(markdown, v)
			require.NoError(t, err)
			assert.Empty(t, undecoded,
				"%s documents keys platformd never decodes; delete them or "+
					"point to the flag that exists (00 L9, #565)", doc)
		})
	}
}

func TestUndecodedDaemonKeys_ReportsStaleSchema(t *testing.T) {
	v, _ := newDaemonViper(t)
	markdown := []byte("```yaml\n" +
		"daemon:\n" +
		"  socket_path: /run/platformd.sock\n" +
		"  rest: {bind-host: 127.0.0.1, port: 8443, tls_cert_file: /x.crt}\n" +
		"```\n\n" +
		"```yaml\n" +
		"grpc:\n" +
		"  enabled: true\n" +
		"```\n")

	undecoded, err := undecodedDaemonKeys(markdown, v)
	require.NoError(t, err)
	assert.Equal(t, []string{"daemon.rest.tls_cert_file", "daemon.socket_path", "grpc"}, undecoded)
}

func TestUndecodedDaemonKeys_RejectsMalformedYAML(t *testing.T) {
	v, _ := newDaemonViper(t)
	markdown := []byte("```yaml\ndaemon: [unclosed\n```\n")

	_, err := undecodedDaemonKeys(markdown, v)
	assert.Error(t, err)
}
