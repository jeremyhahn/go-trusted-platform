package diskimage

import (
	"os"

	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
)

// mergeOverrides deep-merges the overrides file onto the platform config
// template and returns the path of the merged temporary file, as `iso
// create --overrides` does.
func mergeOverrides(template, overrides string) (string, error) {
	if template == "" {
		return "", ErrBuildFailed{Reason: "--overrides requires a --platform-config template"}
	}
	merged, err := config.DeepMergeYAMLFiles(template, overrides)
	if err != nil {
		return "", ErrBuildFailed{Reason: "merging overrides: " + err.Error()}
	}
	tmp, err := os.CreateTemp("", "platformd-merged-*.yaml")
	if err != nil {
		return "", ErrBuildFailed{Reason: "creating the merged config: " + err.Error()}
	}
	if _, err := tmp.Write(merged); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", ErrBuildFailed{Reason: "writing the merged config: " + err.Error()}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", ErrBuildFailed{Reason: "writing the merged config: " + err.Error()}
	}
	return tmp.Name(), nil
}
