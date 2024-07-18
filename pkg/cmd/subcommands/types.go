package subcommands

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
)

var (
	App        *app.App
	TPM        tpm2.TrustedPlatformModule2
	CAParams   ca.CAParams
	InitParams *app.AppInitParams
	CACN,
	CAAlgorithm,
	CAKeyName,
	EKCert,
	CAFile,
	CACertCN,
	CASansDNS,
	CASansIPs,
	CASansEmails string
)

func init() {
	InitParams = &app.AppInitParams{}
}
