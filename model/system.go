package model

import (
	"github.com/jeremyhahn/go-trusted-platform/app"
)

type SystemStruct struct {
	Mode     string          `json:"mode"`
	Version  *app.AppVersion `json:"version"`
	Services int             `json:"farms"`
	Runtime  *SystemRuntime  `json:"runtime"`
}

type SystemRuntime struct {
	Version     string `json:"version"`
	Goroutines  int    `json:"goroutines"`
	Cpus        int    `json:"cpus"`
	Cgo         int64  `json:"cgo"`
	HeapSize    uint64 `json:"heapAlloc"`
	Alloc       uint64 `json:"alloc"`
	Sys         uint64 `json:"sys"`
	Mallocs     uint64 `json:"mallocs"`
	Frees       uint64 `json:"frees"`
	NumGC       uint32 `json:"gc"`
	NumForcedGC uint32 `json:"forcedgc"`
}
