// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package webservice

import "fmt"

// ErrCertReloaderUnavailable reports that the live listener has no certificate
// reloader, so a renewed certificate cannot be put into service without a
// restart.
type ErrCertReloaderUnavailable struct {
	Webservice string
}

func (e ErrCertReloaderUnavailable) Error() string {
	return fmt.Sprintf("webservice: %s has no certificate reloader; a renewed "+
		"certificate cannot be served until platformd restarts", e.Webservice)
}

// ErrCertReloadFailed wraps a failure to put a renewed certificate into service
// on the running listener.
type ErrCertReloadFailed struct {
	Webservice string
	Cause      error
}

func (e ErrCertReloadFailed) Error() string {
	return fmt.Sprintf("webservice: %s certificate reload failed: %v",
		e.Webservice, e.Cause)
}

func (e ErrCertReloadFailed) Unwrap() error { return e.Cause }
