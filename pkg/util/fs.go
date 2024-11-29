package util

import (
	"io"
	"os"
)

func IsEmpty(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	if _, err = f.Readdirnames(1); err == io.EOF {
		return true
	}
	return false
}
