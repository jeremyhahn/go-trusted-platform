package firstboot

import (
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}
