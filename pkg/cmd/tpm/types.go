package tpm

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
)

var (
	App        *app.App
	InitParams *app.AppInitParams
	DevicePath string
)

func init() {
	InitParams = &app.AppInitParams{}
}
