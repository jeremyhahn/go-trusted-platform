package entities

// Error represents an ACME error as per RFC 8555.
type Error struct {
	Type        string          `json:"type"`
	Detail      string          `json:"detail"`
	Status      int             `json:"-"`
	SubProblems []SubProblem    `json:"subproblems,omitempty"`
	Identifier  *ACMEIdentifier `json:"identifier,omitempty"`
	Instance    string          `json:"instance,omitempty"`
}

// Implements the error interface
func (e *Error) Error() string {
	return e.Detail
}

// NewError creates a new ACME error.
func NewError(errType, detail string, status int, subproblems []SubProblem) *Error {
	return &Error{
		Type:        "urn:ietf:params:acme:error:" + errType,
		Detail:      detail,
		Status:      status,
		SubProblems: subproblems,
	}
}

// SubProblem represents a subproblem in a compound error per RFC 8555.
type SubProblem struct {
	Type       string          `json:"type"`
	Detail     string          `json:"detail"`
	Identifier *ACMEIdentifier `json:"identifier,omitempty"`
}
