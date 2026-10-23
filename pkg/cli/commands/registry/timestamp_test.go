package registry

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnixSecondsRendersRFC3339 proves inspect and list emit created_at and
// pushed_at as RFC 3339 strings, so a client decodes them into time.Time.
func TestUnixSecondsRendersRFC3339(t *testing.T) {
	item := ImageListItem{CreatedAt: 1704067200, PushedAt: 1704153600}

	data, err := json.Marshal(item)
	require.NoError(t, err)

	var decoded struct {
		CreatedAt time.Time `json:"created_at"`
		PushedAt  time.Time `json:"pushed_at"`
	}
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), decoded.CreatedAt)
	assert.Equal(t, time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC), decoded.PushedAt)

	yamlValue, err := unixSeconds(1704067200).MarshalYAML()
	require.NoError(t, err)
	assert.Equal(t, "2024-01-01T00:00:00Z", yamlValue)
}

// TestUnixSecondsRejectsNumberDecode proves the rendered form is no longer
// the bare number the registry suite's CLI adapter failed to decode.
func TestUnixSecondsRejectsNumberDecode(t *testing.T) {
	manifest := InspectResult{Manifest: &ImageManifest{CreatedAt: 1234567890}}

	data, err := json.Marshal(manifest)
	require.NoError(t, err)

	var asNumber struct {
		Manifest struct {
			CreatedAt int64 `json:"created_at"`
		} `json:"manifest"`
	}
	assert.Error(t, json.Unmarshal(data, &asNumber), "created_at must not render as a number")
}
