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

//go:build integration

package helpers

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSecretsCLI records the arguments platformctl was called with and answers
// with a canned stdout or error.
type fakeSecretsCLI struct {
	args   []string
	output string
	err    error
}

func (f *fakeSecretsCLI) run(_ context.Context, args ...string) ([]byte, error) {
	f.args = args
	return []byte(f.output), f.err
}

func TestSecretsCLIBuildsTheDocumentedArguments(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name   string
		call   func(SecretsCLI) error
		output string
		want   []string
	}{
		{
			name: "store",
			call: func(s SecretsCLI) error {
				_, err := s.Store(ctx, "db", []byte("pw"), "desc", map[string]string{"z": "1", "a": "2"})
				return err
			},
			output: `{"name":"db","version":1}`,
			want:   []string{"kms", "secrets", "store", "db", "--value", "cHc=", "--base64", "--description", "desc", "--tag", "a=2", "--tag", "z=1"},
		},
		{
			name:   "store without description or tags",
			call:   func(s SecretsCLI) error { _, err := s.Store(ctx, "db", []byte("pw"), "", nil); return err },
			output: `{"name":"db","version":1}`,
			want:   []string{"kms", "secrets", "store", "db", "--value", "cHc=", "--base64"},
		},
		{
			name:   "get",
			call:   func(s SecretsCLI) error { _, err := s.Get(ctx, "db"); return err },
			output: `{"name":"db"}`,
			want:   []string{"kms", "secrets", "get", "db"},
		},
		{
			name:   "list with limit",
			call:   func(s SecretsCLI) error { _, err := s.List(ctx, 2); return err },
			output: `{"secrets":[]}`,
			want:   []string{"kms", "secrets", "list", "--limit", "2"},
		},
		{
			name:   "list with the default limit",
			call:   func(s SecretsCLI) error { _, err := s.List(ctx, 0); return err },
			output: `{"secrets":[]}`,
			want:   []string{"kms", "secrets", "list"},
		},
		{
			name:   "delete",
			call:   func(s SecretsCLI) error { _, err := s.Delete(ctx, "db"); return err },
			output: `{"name":"db","deleted":true}`,
			want:   []string{"kms", "secrets", "delete", "db"},
		},
		{
			name:   "rotate",
			call:   func(s SecretsCLI) error { _, err := s.Rotate(ctx, "db", []byte("pw")); return err },
			output: `{"name":"db","old_version":1,"new_version":2}`,
			want:   []string{"kms", "secrets", "rotate", "db", "--value", "cHc=", "--base64"},
		},
		{
			name:   "version",
			call:   func(s SecretsCLI) error { _, err := s.Version(ctx, "db", 3); return err },
			output: `{"name":"db","version":3}`,
			want:   []string{"kms", "secrets", "version", "db", "3"},
		},
		{
			name:   "versions",
			call:   func(s SecretsCLI) error { _, err := s.Versions(ctx, "db"); return err },
			output: `{"name":"db","versions":[]}`,
			want:   []string{"kms", "secrets", "versions", "db"},
		},
		{
			name:   "rollback",
			call:   func(s SecretsCLI) error { _, err := s.Rollback(ctx, "db", 1); return err },
			output: `{"name":"db","new_version":4}`,
			want:   []string{"kms", "secrets", "rollback", "db", "1"},
		},
		{
			name:   "status enable",
			call:   func(s SecretsCLI) error { _, err := s.SetStatus(ctx, "db", true); return err },
			output: `{"name":"db","status":"enabled"}`,
			want:   []string{"kms", "secrets", "status", "enable", "db"},
		},
		{
			name:   "status disable",
			call:   func(s SecretsCLI) error { _, err := s.SetStatus(ctx, "db", false); return err },
			output: `{"name":"db","status":"disabled"}`,
			want:   []string{"kms", "secrets", "status", "disable", "db"},
		},
		{
			name:   "policy get",
			call:   func(s SecretsCLI) error { _, err := s.Policy(ctx, "db"); return err },
			output: `{"name":"db"}`,
			want:   []string{"kms", "secrets", "policy", "get", "db"},
		},
		{
			name: "policy set",
			call: func(s SecretsCLI) error {
				_, err := s.SetPolicy(ctx, "db", SecretsCLIPolicyOptions{Enabled: true, IntervalSeconds: 3600, RetainVersions: 5, RotationLambda: "fn"})
				return err
			},
			output: `{"name":"db","enabled":true}`,
			want:   []string{"kms", "secrets", "policy", "set", "db", "--enabled=true", "--interval", "3600s", "--retain-versions", "5", "--rotation-lambda", "fn"},
		},
		{
			name:   "policy set disabled",
			call:   func(s SecretsCLI) error { _, err := s.SetPolicy(ctx, "db", SecretsCLIPolicyOptions{}); return err },
			output: `{"name":"db","enabled":false}`,
			want:   []string{"kms", "secrets", "policy", "set", "db", "--enabled=false"},
		},
		{
			name:   "prefix list with data",
			call:   func(s SecretsCLI) error { _, err := s.PrefixList(ctx, "app/", true); return err },
			output: `{"prefix":"app/","secrets":[]}`,
			want:   []string{"kms", "secrets", "prefix", "list", "app/", "--include-data"},
		},
		{
			name:   "prefix list names only",
			call:   func(s SecretsCLI) error { _, err := s.PrefixList(ctx, "app/", false); return err },
			output: `{"prefix":"app/","secrets":[]}`,
			want:   []string{"kms", "secrets", "prefix", "list", "app/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeSecretsCLI{output: tt.output}
			require.NoError(t, tt.call(SecretsCLI{Run: fake.run}))
			assert.Equal(t, tt.want, fake.args)
		})
	}
}

func TestSecretsCLIDecodesTheJSONOutput(t *testing.T) {
	fake := &fakeSecretsCLI{output: `{"name":"db","version":2,"value":"cHc=","metadata":{"env":"prod"},"created_at":"2026-10-21T10:00:00Z","created_by":"admin"}`}

	secret, err := SecretsCLI{Run: fake.run}.Get(context.Background(), "db")

	require.NoError(t, err)
	assert.Equal(t, "db", secret.Name)
	assert.Equal(t, uint64(2), secret.Version)
	assert.Equal(t, []byte("pw"), secret.Value)
	assert.Equal(t, map[string]string{"env": "prod"}, secret.Metadata)
	assert.Equal(t, time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC), secret.CreatedAt)
	assert.Equal(t, "admin", secret.CreatedBy)
}

func TestSecretsCLIReportsAnUnservedVerbAsAnUpstreamGap(t *testing.T) {
	fake := &fakeSecretsCLI{err: errTestCLIFailed{stderr: "Error: embedded: unknown method: quicbaas.Secrets.Rotate"}}

	_, err := SecretsCLI{Run: fake.run}.Rotate(context.Background(), "db", []byte("pw"))

	var gap ErrCLIUpstreamGap
	require.ErrorAs(t, err, &gap)
	assert.Equal(t, "kms secrets rotate", gap.Operation)
	assert.Equal(t, SecretsSDKGapIssue, gap.Issue)
}

func TestSecretsCLIPassesOtherCommandFailuresThrough(t *testing.T) {
	cause := errTestCLIFailed{stderr: "Error: get secret db: secret not found"}
	fake := &fakeSecretsCLI{err: cause}

	_, err := SecretsCLI{Run: fake.run}.Get(context.Background(), "db")

	assert.Equal(t, cause, err)
}

func TestSecretsCLIRejectsOutputThatIsNotJSON(t *testing.T) {
	fake := &fakeSecretsCLI{output: "Secret db stored"}

	_, err := SecretsCLI{Run: fake.run}.Store(context.Background(), "db", []byte("pw"), "", nil)

	var parse ErrSecretsCLIOutput
	require.ErrorAs(t, err, &parse)
	assert.Equal(t, "store", parse.Operation)
	assert.Equal(t, "Secret db stored", parse.Output)
}
