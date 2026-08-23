// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package app

import "fmt"

// ErrCertInstallerMissing reports that no installer is registered for a
// webservice, so a renewed certificate cannot be put into service.
type ErrCertInstallerMissing struct {
	Webservice string
}

func (e ErrCertInstallerMissing) Error() string {
	return fmt.Sprintf("app: webservice %s has no certificate installer; the "+
		"renewed certificate is stored but the live listener still serves the "+
		"previous one", e.Webservice)
}

// ErrCertInstallFailed wraps a failure to put a renewed certificate into service
// on the running listener.
type ErrCertInstallFailed struct {
	Webservice string
	Cause      error
}

func (e ErrCertInstallFailed) Error() string {
	return fmt.Sprintf("app: webservice %s certificate install failed, the live "+
		"listener still serves the previous certificate: %v", e.Webservice, e.Cause)
}

func (e ErrCertInstallFailed) Unwrap() error { return e.Cause }
