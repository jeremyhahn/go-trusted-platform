package util

import (
	"os"
	"strings"
)

func FileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func FileName(path string) (string, string) {
	// Parse the certificate file name from the URL
	filePieces := strings.Split(path, "/")
	filename := filePieces[len(filePieces)-1]
	namePieces := strings.Split(filename, ".")
	extension := ""
	if len(namePieces) > 1 {
		extension = namePieces[1]
	}
	return namePieces[0], extension
}
