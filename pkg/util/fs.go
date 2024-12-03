package util

import (
	"io"
	"os"
	"strings"
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

func EscapeFilePath(path string) string {
	// List of characters to escape in Linux file paths
	specialChars := ` !"#$%&'()*,:;<=>?@[\]^` + "`" + `{|}~`

	// Replace each special character with an escaped version
	var escapedPath strings.Builder
	for _, ch := range path {
		if strings.ContainsRune(specialChars, ch) || ch == '\\' {
			escapedPath.WriteRune('\\')
		}
		escapedPath.WriteRune(ch)
	}
	return escapedPath.String()
}
