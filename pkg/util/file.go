package util

import (
	"fmt"
	"os"
	"strings"
)

func FileExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

func FileName(path string) (string, string) {
	pathPieces := strings.Split(path, "/")
	filename := pathPieces[len(pathPieces)-1]
	namePieces := strings.Split(filename, ".")
	extension := ""
	if len(namePieces) > 1 {
		extension = namePieces[1]
	}
	return namePieces[0], fmt.Sprintf(".%s", extension)
}
