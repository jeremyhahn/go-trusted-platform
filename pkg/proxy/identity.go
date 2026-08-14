package proxy

import (
	"net/http"
	"strconv"
	"strings"
)

// Trusted identity headers injected toward backends after an allow decision.
// Every inbound occurrence is stripped by stripIdentityHeaders before
// routing, so backends can trust these values unconditionally.
const (
	headerAuthorization     = "Authorization"
	headerTPClientID        = "X-TP-Client-ID"
	headerTPDeviceID        = "X-TP-Device-ID"
	headerTPClientZone      = "X-TP-Client-Zone"
	headerTPAuthMethod      = "X-TP-Auth-Method"
	headerTPAttested        = "X-TP-Attested"
	headerTPCertFingerprint = "X-TP-Cert-Fingerprint"
)

// injectIdentity sets the trusted identity headers for the authenticated
// caller on the forwarded request. Empty identity fields are omitted;
// X-TP-Attested is always set so backends never have to distinguish absent
// from false.
func injectIdentity(h http.Header, id *ClientIdentity) {
	if id == nil {
		return
	}
	if xfcc := buildXFCC(id); xfcc != "" {
		h.Set(headerForwardedClientCert, xfcc)
	}
	if id.ID != "" {
		h.Set(headerTPClientID, id.ID)
	}
	if id.DeviceID != "" {
		h.Set(headerTPDeviceID, id.DeviceID)
	}
	if id.Zone != "" {
		h.Set(headerTPClientZone, id.Zone)
	}
	if id.AuthMethod != "" {
		h.Set(headerTPAuthMethod, id.AuthMethod)
	}
	h.Set(headerTPAttested, strconv.FormatBool(id.Attested))
	if id.CertFingerprint != "" {
		h.Set(headerTPCertFingerprint, id.CertFingerprint)
	}
}

// buildXFCC renders the Envoy-compatible X-Forwarded-Client-Cert value:
// Hash=<sha256hex>;Subject="<escaped DN>";URI=<first URI SAN>. Only present
// elements are included; an identity with no certificate detail yields "".
func buildXFCC(id *ClientIdentity) string {
	parts := make([]string, 0, 3)
	if id.CertFingerprint != "" {
		parts = append(parts, "Hash="+id.CertFingerprint)
	}
	if id.subjectDN != "" {
		parts = append(parts, `Subject="`+xfccEscape(id.subjectDN)+`"`)
	}
	if id.uriSAN != "" {
		parts = append(parts, "URI="+xfccValue(id.uriSAN))
	}
	return strings.Join(parts, ";")
}

// xfccValue quotes an XFCC element value when it contains characters that
// would break unquoted parsing (comma, semicolon, equals, double quote).
func xfccValue(v string) string {
	if strings.ContainsAny(v, `,;="`) {
		return `"` + xfccEscape(v) + `"`
	}
	return v
}

// xfccEscape escapes a value for use inside a double-quoted XFCC element:
// backslashes and double quotes are backslash-escaped.
func xfccEscape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	return strings.ReplaceAll(v, `"`, `\"`)
}
