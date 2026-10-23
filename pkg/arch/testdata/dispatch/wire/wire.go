// Package wire is a dispatch-check fixture: opcodes and statuses.
package wire

const (
	OpList byte = iota + 1
	OpGet
	OpDelete
)

const (
	StatusOK             = 200
	StatusNotImplemented = 501
)

type Request struct {
	Opcode byte
}

type Response struct {
	Status int
}
