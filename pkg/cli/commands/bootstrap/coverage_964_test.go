package bootstrap

import (
	"context"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestPruneToJSON_EdgeBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "all whitespace", body: " \n\t ", want: ""},
		{name: "array body", body: "  [1, 2, 3]\n", want: "[]"},
		{name: "object body", body: `{"status":"ok"}`, want: "{}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(pruneToJSON([]byte(tt.body))))
		})
	}
}

func TestIPString(t *testing.T) {
	assert.Equal(t, "", ipString(nil))
	assert.Equal(t, "192.0.2.7", ipString(net.ParseIP("192.0.2.7")))
}

func TestTargetSoCSuffix(t *testing.T) {
	assert.Equal(t, "", targetSoCSuffix(""))
	assert.Equal(t, ", target-soc bcm2711", targetSoCSuffix("bcm2711"))
}

func TestCheckNodeHealth_NilClientIsUnknown(t *testing.T) {
	assert.Equal(t, "unknown", checkNodeHealth(context.Background(), nil, "192.0.2.1", []int{8443}))
}

func TestProbeNodeHealth_BadHostPortIsUnreachable(t *testing.T) {
	// A control character makes the URL unparsable, so the request is never
	// built and nothing is dialled.
	got := probeNodeHealth(context.Background(), &http.Client{}, "bad\x7fhost:8443")
	assert.Equal(t, "unreachable", got)
}

// cov964Execute runs cmd through cobra with args and returns its error.
func cov964Execute(cmd *cobra.Command, args ...string) error {
	cmd.SetArgs(args)
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	return cmd.Execute()
}

func TestPXECommands_MissingConfigFailsToLoad(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }
	tests := []struct {
		name string
		cmd  func() *cobra.Command
	}{
		{name: "discover", cmd: func() *cobra.Command { return newDiscoverCommand(getFlags) }},
		{name: "teardown", cmd: func() *cobra.Command { return newTeardownCommand(getFlags) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			missing := filepath.Join(t.TempDir(), "missing.yaml")
			err := cov964Execute(tt.cmd(), "--config", missing)
			var loadErr ErrPXEConfigLoadFailed
			require.ErrorAs(t, err, &loadErr)
			assert.Equal(t, missing, loadErr.Path)
		})
	}
}

func TestSecretsCommands_MissingConfigFailsToRead(t *testing.T) {
	tests := []struct {
		name string
		cmd  func(getFlags func() *cli.CommonFlags) *cobra.Command
	}{
		{name: "status", cmd: newSecretsStatusCommand},
		{name: "verify", cmd: newSecretsVerifyCommand},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := newSocketFlags(t, cli.OutputFormatTable, nil)
			missing := filepath.Join(t.TempDir(), "missing.yaml")
			err := cov964Execute(tt.cmd(func() *cli.CommonFlags { return flags }), "--config", missing)
			var readErr ErrConfigFileReadFailed
			require.ErrorAs(t, err, &readErr)
			assert.Equal(t, missing, readErr.Path)
		})
	}
}

func TestSecretsResolveCommand_UnknownSchemeIsInvalid(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }
	err := cov964Execute(newSecretsResolveCommand(getFlags), "plain-value")
	var uriErr ErrInvalidSecretURI
	require.ErrorAs(t, err, &uriErr)
	assert.Equal(t, "plain-value", uriErr.URI)
}
