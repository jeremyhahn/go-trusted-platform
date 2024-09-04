package keystore

import (
	"os"
	"testing"

	"github.com/op/go-logging"
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
	logger := logging.MustGetLogger("certificate-authority")
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	// backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(logFormatter)

	DebugAvailableHashes(logger)
	DebugAvailableSignatureAkgorithms(logger)

	return logger
}
