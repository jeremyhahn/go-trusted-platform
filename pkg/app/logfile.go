package app

import "strings"

// logFileName is the platform log file's name. Name is ldflag-populated and
// is empty on a bare `go build`, which would produce a hidden ".log" file,
// so it falls back to a stable name the OpenRC init script and operators
// can find.
func logFileName() string {
	if Name == "" {
		return "platformd.log"
	}
	return Name + ".log"
}

// validateLogDir rejects a log directory that cannot name a directory,
// before any filesystem call: an empty LogDir would put the log file at
// "/platformd.log".
func validateLogDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return LogDirInvalidError{Dir: dir, Reason: "empty"}
	}
	if strings.ContainsRune(dir, 0) {
		return LogDirInvalidError{Dir: dir, Reason: "contains a NUL byte"}
	}
	return nil
}
