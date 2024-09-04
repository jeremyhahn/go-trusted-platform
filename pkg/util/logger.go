package util

import (
	"os"

	"github.com/op/go-logging"
)

// Creates a new file and STDOUT logger with short package,
// function name, and logging level prefixed to messages.
func Logger() *logging.Logger {
	stdout := logging.NewLogBackend(os.Stdout, "", 0)
	//logging.SetBackend(stdout)
	logger := logging.MustGetLogger("trusted-platform")
	logFormat := logging.MustStringFormatter(
		`%{color}%{time:15:04:05.000} %{shortpkg}.%{shortfunc} %{level:.4s} %{id:03x}%{color:reset} %{message}`,
	)
	logFormatter := logging.NewBackendFormatter(stdout, logFormat)
	// backends := logging.MultiLogger(stdout, logFormatter)
	logging.SetBackend(logFormatter)
	return logger
}
