// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package daemon

import (
	"errors"
	"strings"
	"testing"
)

func TestErrGetStatusFailed(t *testing.T) {
	cause := errors.New("connection refused")
	err := &ErrGetStatusFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get daemon status") {
			t.Errorf("Error() = %v, should contain 'failed to get daemon status'", msg)
		}
		if !strings.Contains(msg, "connection refused") {
			t.Errorf("Error() = %v, should contain cause", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		unwrapped := err.Unwrap()
		if unwrapped != cause {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
		}
	})
}

func TestErrGetHealthFailed(t *testing.T) {
	cause := errors.New("timeout")
	err := &ErrGetHealthFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get daemon health") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrShutdownFailed(t *testing.T) {
	cause := errors.New("services still running")
	err := &ErrShutdownFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to shutdown daemon") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrRestartFailed(t *testing.T) {
	cause := errors.New("service dependency failed")
	err := &ErrRestartFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to restart platform") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrGetVersionFailed(t *testing.T) {
	cause := errors.New("rpc error")
	err := &ErrGetVersionFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get daemon version") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrGetSystemInfoFailed(t *testing.T) {
	cause := errors.New("not available")
	err := &ErrGetSystemInfoFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get system info") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrGetTPMInfoFailed(t *testing.T) {
	cause := errors.New("TPM not present")
	err := &ErrGetTPMInfoFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get TPM info") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrGetConfigFailed(t *testing.T) {
	cause := errors.New("access denied")
	err := &ErrGetConfigFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get configuration") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrUpdateConfigFailed(t *testing.T) {
	cause := errors.New("validation error")

	t.Run("Error with section name", func(t *testing.T) {
		err := &ErrUpdateConfigFailed{Section: "logging", Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "logging") {
			t.Errorf("Error() = %v, should contain section name", msg)
		}
		if !strings.Contains(msg, "failed to update configuration section") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Error without section name", func(t *testing.T) {
		err := &ErrUpdateConfigFailed{Section: "", Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "failed to update configuration:") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		err := &ErrUpdateConfigFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrReloadConfigFailed(t *testing.T) {
	cause := errors.New("file not found")
	err := &ErrReloadConfigFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to reload configuration") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrStartServiceFailed(t *testing.T) {
	cause := errors.New("port in use")
	err := &ErrStartServiceFailed{Service: "webservice", Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to start service webservice") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrStopServiceFailed(t *testing.T) {
	cause := errors.New("timeout")
	err := &ErrStopServiceFailed{Service: "tpm", Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to stop service tpm") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrRestartServiceFailed(t *testing.T) {
	cause := errors.New("dependency failed")
	err := &ErrRestartServiceFailed{Service: "sdn", Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to restart service sdn") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrGetServiceStatusFailed(t *testing.T) {
	cause := errors.New("service not found")
	err := &ErrGetServiceStatusFailed{Service: "dns", Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to get status for service dns") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrListServicesFailed(t *testing.T) {
	cause := errors.New("internal error")
	err := &ErrListServicesFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to list services") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrListEntityTypesFailed(t *testing.T) {
	cause := errors.New("database error")
	err := &ErrListEntityTypesFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to list entity types") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrDumpEntityTypeFailed(t *testing.T) {
	cause := errors.New("serialization error")

	t.Run("Error with entity type", func(t *testing.T) {
		err := &ErrDumpEntityTypeFailed{EntityType: "users", Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "failed to dump entity type users") {
			t.Errorf("Error() = %v, should contain entity type", msg)
		}
	})

	t.Run("Error without entity type", func(t *testing.T) {
		err := &ErrDumpEntityTypeFailed{EntityType: "", Cause: cause}
		msg := err.Error()
		if !strings.Contains(msg, "failed to dump entity types") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		err := &ErrDumpEntityTypeFailed{Cause: cause}
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrStreamEventsFailed(t *testing.T) {
	cause := errors.New("connection lost")
	err := &ErrStreamEventsFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to open event stream") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrStreamLogsFailed(t *testing.T) {
	cause := errors.New("permission denied")
	err := &ErrStreamLogsFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to open log stream") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrStreamMetricsFailed(t *testing.T) {
	cause := errors.New("not supported")
	err := &ErrStreamMetricsFailed{Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to open metrics stream") {
			t.Errorf("Error() = %v, should contain expected message", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestErrStreamRecvFailed(t *testing.T) {
	cause := errors.New("stream closed")
	err := &ErrStreamRecvFailed{StreamType: "events", Cause: cause}

	t.Run("Error returns formatted message", func(t *testing.T) {
		msg := err.Error()
		if !strings.Contains(msg, "failed to receive from events stream") {
			t.Errorf("Error() = %v, should contain stream type", msg)
		}
	})

	t.Run("Unwrap returns cause", func(t *testing.T) {
		if err.Unwrap() != cause {
			t.Errorf("Unwrap() = %v, want %v", err.Unwrap(), cause)
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	t.Run("ErrSystemInfoNotAvailable is defined", func(t *testing.T) {
		if ErrSystemInfoNotAvailable == nil {
			t.Error("ErrSystemInfoNotAvailable should not be nil")
		}
		if !strings.Contains(ErrSystemInfoNotAvailable.Error(), "system info not available") {
			t.Errorf("ErrSystemInfoNotAvailable.Error() = %v, should contain expected message", ErrSystemInfoNotAvailable.Error())
		}
	})

	t.Run("ErrTPMInfoNotAvailable is defined", func(t *testing.T) {
		if ErrTPMInfoNotAvailable == nil {
			t.Error("ErrTPMInfoNotAvailable should not be nil")
		}
		if !strings.Contains(ErrTPMInfoNotAvailable.Error(), "TPM info not available") {
			t.Errorf("ErrTPMInfoNotAvailable.Error() = %v, should contain expected message", ErrTPMInfoNotAvailable.Error())
		}
	})

	t.Run("ErrNilConfigSection is defined", func(t *testing.T) {
		if ErrNilConfigSection == nil {
			t.Error("ErrNilConfigSection should not be nil")
		}
		if !strings.Contains(ErrNilConfigSection.Error(), "config section cannot be nil") {
			t.Errorf("ErrNilConfigSection.Error() = %v, should contain expected message", ErrNilConfigSection.Error())
		}
	})

	t.Run("ErrNilRequest is defined", func(t *testing.T) {
		if ErrNilRequest == nil {
			t.Error("ErrNilRequest should not be nil")
		}
		if !strings.Contains(ErrNilRequest.Error(), "request cannot be nil") {
			t.Errorf("ErrNilRequest.Error() = %v, should contain expected message", ErrNilRequest.Error())
		}
	})
}

func TestErrorsIsChain(t *testing.T) {
	t.Run("errors.Is works with wrapped errors", func(t *testing.T) {
		cause := ErrSystemInfoNotAvailable
		err := &ErrGetSystemInfoFailed{Cause: cause}

		if !errors.Is(err, ErrSystemInfoNotAvailable) {
			t.Error("errors.Is should find wrapped sentinel error")
		}
	})

	t.Run("errors.As works with typed errors", func(t *testing.T) {
		err := &ErrGetVersionFailed{Cause: errors.New("test")}

		var versionErr *ErrGetVersionFailed
		if !errors.As(err, &versionErr) {
			t.Error("errors.As should find typed error")
		}
	})
}
