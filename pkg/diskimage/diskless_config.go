package diskimage

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap"
)

// disklessPlatformConfig is where the installer copies the platform config
// into the root, relative to the root.
const disklessPlatformConfig = "etc/trusted-platform/config.yaml"

// DisklessRootConfigSecretError reports a platform config in a diskless root
// that holds secrets as plaintext: fields the config schema marks
// `secret:"true"` whose value is a literal rather than a secret reference
// (kms://, env://, file:// ...). The root is served to every node and to
// anyone who can fetch the image, so a credential in it is a credential
// everyone holds.
type DisklessRootConfigSecretError struct {
	// Path is relative to the root.
	Path string
	// Fields are the YAML paths of the plaintext secrets, in document order.
	Fields []string
}

func (e DisklessRootConfigSecretError) Error() string {
	return "diskless root: /" + e.Path + ": " + strings.Join(e.Fields, ", ") +
		" hold plaintext secrets; use a secret reference (kms://, env://, file:// ...); the root is public"
}

// refuseRootConfigSecrets refuses a root whose platform config holds a
// secret-tagged field with a plaintext value. A root without a platform
// config passes.
func refuseRootConfigSecrets(root string) error {
	data, err := os.ReadFile(filepath.Join(root, disklessPlatformConfig))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	fields, err := bootstrap.PlaintextSecretFields(data, reflect.TypeFor[app.App]())
	if err != nil {
		return err
	}
	if len(fields) > 0 {
		return DisklessRootConfigSecretError{Path: disklessPlatformConfig, Fields: fields}
	}
	return nil
}
