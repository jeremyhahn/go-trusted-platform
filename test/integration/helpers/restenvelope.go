package helpers

import "encoding/json"

// ErrRESTNotEnveloped reports a v1 REST reply that is not the platform's
// response envelope ({"code", "success", "payload"}).
type ErrRESTNotEnveloped struct {
	Body string
	Err  error
}

func (e ErrRESTNotEnveloped) Error() string {
	if e.Err != nil {
		return "REST reply is not a response envelope: " + e.Err.Error() + ": " + e.Body
	}
	return "REST reply is not a response envelope: " + e.Body
}

func (e ErrRESTNotEnveloped) Unwrap() error { return e.Err }

// restEnvelope mirrors sdk/go/wire/restwire.WebServiceResponse, the
// envelope every v1 REST handler writes through the response writer.
type restEnvelope struct {
	Success *bool           `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

// RESTPayload returns the payload inside a v1 REST reply's envelope. An
// empty reply has no payload and returns nil; a reply without the envelope's
// "success" field is an ErrRESTNotEnveloped, so a handler that stops
// enveloping is reported instead of decoding into an empty entity.
func RESTPayload(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	var envelope restEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, ErrRESTNotEnveloped{Body: string(body), Err: err}
	}
	if envelope.Success == nil {
		return nil, ErrRESTNotEnveloped{Body: string(body)}
	}
	return envelope.Payload, nil
}
