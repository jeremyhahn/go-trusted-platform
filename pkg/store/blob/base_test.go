package blob

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/op/go-logging"
	"github.com/spf13/afero"
)

var (
	TEST_DATA_DIR = "./testdata"
	TEST_CN       = "exapmle.com"
	TEST_TMP_DIR  = ""
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	// os.RemoveAll(TEST_DATA_DIR)
}

func setup() {
	os.RemoveAll(TEST_DATA_DIR)
}

func defaultLogger() *logging.Logger {
	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	//logging.SetBackend(stdout)
	logger := logging.MustGetLogger("store/blob")
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	// backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(logFormatter)

	return logger
}

func defaultStore() BlobStorer {

	logger := defaultLogger()

	// Create a temp directory for each instantiation
	// so parallel tests don't corrupt each other.
	buf := make([]byte, 8)
	_, err := rand.Reader.Read(buf)
	if err != nil {
		panic(err)
	}
	tmpDir := hex.EncodeToString(buf)

	caCN := "example.com"
	TEST_TMP_DIR = fmt.Sprintf("%s/%s/%s", TEST_DATA_DIR, tmpDir, caCN)

	fs := afero.NewMemMapFs()
	store, err := NewFSBlobStore(logger, fs, TEST_TMP_DIR, nil)
	if err != nil {
		logger.Fatal(err)
	}

	return store
}
