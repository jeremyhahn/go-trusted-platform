package pkcs11

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/op/go-logging"
)

var SOFTHSM_CONF = []byte(`
# SoftHSM v2 configuration file

directories.tokendir = trusted-data/softhsm2
objectstore.backend = file
objectstore.umask = 0077

# ERROR, WARNING, INFO, DEBUG
log.level = ERROR

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false

# Enable and disable PKCS#11 mechanisms using slots.mechanisms.
slots.mechanisms = ALL

# If the library should reset the state on fork
library.reset_on_fork = false
`)

type Config struct {
	CN             string `yaml:"cn" json:"cn" mapstructure:"cn"`
	Library        string `yaml:"library" json:"library" mapstructure:"library"`
	LibraryConfig  string `yaml:"config" json:"config" mapstructure:"config"`
	Pin            string `yaml:"pin" json:"pin" mapstructure:"pin"`
	PlatformPolicy bool   `yaml:"platform-policy" json:"platform_policy" mapstructure:"platform-policy"`
	Slot           *int   `yaml:"slot" json:"slot" mapstructure:"slot"`
	SOPin          string `yaml:"so-pin" json:"so_pin" mapstructure:"so-pin"`
	TokenLabel     string `yaml:"label" json:"label" mapstructure:"label"`
}

// Initializes SoftHSM with an external shell command to softhsm2-util
func InitSoftHSM(logger *logging.Logger, config *Config) {

	// NOTE: The Golang command package doesn't work with Afero memory fs

	if _, err := os.Stat(config.LibraryConfig); err != nil {
		dir := filepath.Dir(config.LibraryConfig)
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			slog.Error(err.Error())
			os.Exit(-1)
		}
		conf := fmt.Sprintf("%s/softhsm.conf", dir)
		if err := os.WriteFile(conf, SOFTHSM_CONF, os.ModePerm); err != nil {
			slog.Error(err.Error())
			os.Exit(-1)
		}
	}

	// if !util.FileExists(config.LibraryConfig) {
	// 	dir := filepath.Dir(config.LibraryConfig)
	// 	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
	// 		slog.Error(err.Error())
	// 		os.Exit(-1)
	// 	}
	// 	conf := fmt.Sprintf("%s/softhsm.conf", dir)
	// 	if err := afero.WriteFile(fs, conf, SOFTHSM_CONF, os.ModePerm); err != nil {
	// 		slog.Error(err.Error())
	// 		os.Exit(-1)
	// 	}
	// }

	conf, err := os.ReadFile(config.LibraryConfig)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(-1)
	}

	// Create SoftHSM2 directory structure
	re, err := regexp.Compile(`directories.tokendir.*\n`)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(-1)
	}
	matches := re.FindAllString(string(conf), -1)
	if len(matches) > 0 {
		pieces := strings.Split(matches[len(matches)-1], "=")
		if len(pieces) == 2 {
			path := strings.TrimSpace(pieces[1])
			if !util.FileExists(path) {
				if err := os.MkdirAll(path, os.ModePerm); err != nil {
					slog.Error(err.Error())
					os.Exit(-1)
				}
			}

		}
	}

	// cmd2 := exec.Command("cat " + config.LibraryConfig)
	// out, err := cmd2.CombinedOutput()
	// if err != nil {
	// 	slog.Error(err.Error())
	// }
	// fmt.Printf("%s\n", out)

	// softhsm2-util --init-token --slot x --label xxxx --so-pin xxxx --pin xxxx
	app := "softhsm2-util"
	args := []string{
		"--init-token",
		"--slot", "0",
		"--label", config.TokenLabel,
		"--so-pin", config.SOPin,
		"--pin", config.Pin}

	cmd := exec.Command(app, args...)
	stdout, err := cmd.Output()
	// For some reason exit status is 1 for success
	if err != nil {
		if e := (&exec.ExitError{}); errors.As(err, &e) {
			logger.Error(e.Error())
			slog.Error(string(e.Stderr))
		}
	}
	logger.Debug(string(stdout))
}
