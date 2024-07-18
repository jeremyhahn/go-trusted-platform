package keystore

import (
	"os"
	"testing"
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
