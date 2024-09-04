package platform

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

var (
	App        *app.App
	TPM        tpm2.TrustedPlatformModule
	CAParams   *ca.CAParams
	InitParams *app.AppInitParams
)
