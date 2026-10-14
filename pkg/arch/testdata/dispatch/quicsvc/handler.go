// Package quicsvc is a dispatch-check fixture: an opcode dispatcher with one
// stub arm, one stub handler behind an interface field, a guarded 501 that is
// not a stub, and an unknown-opcode fallback.
package quicsvc

import "example.test/dispatch/wire"

type Handler struct {
	store Backend
}

type ErrDeleteNotImplemented struct{}

func (ErrDeleteNotImplemented) Error() string { return "delete not implemented" }

type ErrUnknownOpcode struct {
	Opcode byte
}

func (ErrUnknownOpcode) Error() string { return "unknown opcode" }

func New() *Handler {
	return wrap(&Store{})
}

func wrap(b Backend) *Handler {
	return &Handler{store: b}
}

func (h *Handler) HandleRequest(req *wire.Request) *wire.Response {
	switch req.Opcode {
	case wire.OpList:
		return h.list(req)
	case wire.OpGet:
		return h.get(req)
	case wire.OpDelete:
		return h.errorResponse(wire.StatusNotImplemented, ErrDeleteNotImplemented{}) // stub: arm
	default:
		return h.errorResponse(wire.StatusNotImplemented, ErrUnknownOpcode{Opcode: req.Opcode})
	}
}

func (h *Handler) list(req *wire.Request) *wire.Response {
	if req.Opcode == 0 {
		return h.errorResponse(wire.StatusNotImplemented, ErrDeleteNotImplemented{})
	}
	return h.store.List() // real: list
}

func (h *Handler) get(req *wire.Request) *wire.Response {
	return h.store.Get()
}

func (h *Handler) errorResponse(status int, err error) *wire.Response {
	return &wire.Response{Status: status}
}
