package service

import "github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"

type Service struct {
	ID            uint64
	Name          string
	KeyAttributes *keystore.KeyAttributes
}
