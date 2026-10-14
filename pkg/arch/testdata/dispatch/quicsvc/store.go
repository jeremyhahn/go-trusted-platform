package quicsvc

import "example.test/dispatch/wire"

type Backend interface {
	List() *wire.Response
	Get() *wire.Response
}

type Store struct{}

func (s *Store) List() *wire.Response {
	return &wire.Response{Status: wire.StatusOK}
}

func (s *Store) Get() *wire.Response {
	return &wire.Response{Status: wire.StatusNotImplemented} // stub: handler
}
