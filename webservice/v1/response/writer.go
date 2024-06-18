package response

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/jeremyhahn/go-trusted-platform/service"
	"github.com/op/go-logging"
	"gopkg.in/yaml.v2"
)

type HttpWriter interface {
	Write(w http.ResponseWriter, r *http.Request, status int, response interface{})
	WriteYaml(w http.ResponseWriter, status int, response interface{})
	WriteJson(w http.ResponseWriter, status int, response interface{})
	Success200(w http.ResponseWriter, r *http.Request, payload interface{})
	Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error)
	Error200(w http.ResponseWriter, r *http.Request, err error)
	Error400(w http.ResponseWriter, r *http.Request, err error)
	Error404(w http.ResponseWriter, r *http.Request, err error)
	Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{})
	Error500(w http.ResponseWriter, r *http.Request, err error)
}

type WebServiceResponse struct {
	Code       int         `yaml:"code" json:"code"`
	Error      string      `yaml:"error" json:"error"`
	Success    bool        `yaml:"success" json:"success"`
	Payload    interface{} `yaml:"payload" json:"payload"`
	HttpWriter `yaml:"-" json:"-"`
}

type ResponseWriter struct {
	logger  *logging.Logger
	session service.Session
	HttpWriter
}

func NewResponseWriter(
	logger *logging.Logger,
	session service.Session) HttpWriter {

	return &ResponseWriter{
		logger:  logger,
		session: session}
}

// Sets the session. When present, log messages include session info.
func (writer *ResponseWriter) SetSession(session service.Session) {
	writer.session = session
}

// Writes a response to the http client using the client accept header to determine whether to use a JSON or YAML
// serializer and content-type header. Default is JSON if a valid header can not be found.
func (writer *ResponseWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	acceptHeader := r.Header.Get("accept")
	if acceptHeader == "application/json" || acceptHeader == "text/json" {
		writer.WriteJson(w, status, response)
		return
	}
	if acceptHeader == "application/yaml" || acceptHeader == "text/yaml" {
		writer.WriteYaml(w, status, response)
		return
	}
	// Default to JSON for unknown accept headers
	writer.WriteJson(w, status, response)
}

// Writes a response to the http client using an application/yaml content-type header and YAML serializer
func (writer *ResponseWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	yamlResponse, err := yaml.Marshal(response)
	if err != nil {
		errResponse := WebServiceResponse{Error: fmt.Sprintf("YamlWriter failed to marshal response entity %s %+v", reflect.TypeOf(response), response)}
		errBytes, err := yaml.Marshal(errResponse)
		if err != nil {
			errResponse := WebServiceResponse{Error: fmt.Sprintf("YamlWriter internal server error: %s", err.Error())}
			errBytes, _ := yaml.Marshal(errResponse)
			http.Error(w, string(errBytes), http.StatusInternalServerError)
		}
		http.Error(w, string(errBytes), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(status)
	w.Write(yamlResponse)

	writer.logResponse(w, status, string(yamlResponse))
}

// Writes a response to the http client using an application/json content-type header and JSON serializer
func (writer *ResponseWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		errResponse := WebServiceResponse{Error: fmt.Sprintf("ResponseWriter failed to marshal response entity %s %+v", reflect.TypeOf(response), response)}
		errBytes, err := json.Marshal(errResponse)
		if err != nil {
			errResponse := WebServiceResponse{Error: fmt.Sprintf("ResponseWriter internal server error: %s", err.Error())}
			errBytes, _ := json.Marshal(errResponse)
			http.Error(w, string(errBytes), http.StatusInternalServerError)
		}
		http.Error(w, string(errBytes), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(jsonResponse)

	writer.logResponse(w, status, string(jsonResponse))
}

func (writer *ResponseWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	writer.logRequest(r)
	writer.Write(w, r, http.StatusOK, WebServiceResponse{
		Code:    http.StatusOK,
		Success: true,
		Payload: payload})
}

func (writer *ResponseWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	writer.logRequest(r)
	writer.Write(w, r, http.StatusNotFound, WebServiceResponse{
		Code:    http.StatusNotFound,
		Success: true,
		Error:   err.Error(),
		Payload: payload})
}

func (writer *ResponseWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	writer.logError(r, err)
	writer.Write(w, r, http.StatusOK, WebServiceResponse{
		Code:    http.StatusOK,
		Success: false,
		Payload: err.Error()})
}

func (writer *ResponseWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	writer.logError(r, err)
	writer.Write(w, r, http.StatusBadRequest, WebServiceResponse{
		Code:    http.StatusBadRequest,
		Error:   err.Error(),
		Success: false,
		Payload: nil})
}

func (writer *ResponseWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	writer.logError(r, err)
	writer.Write(w, r, http.StatusNotFound, WebServiceResponse{
		Code:    http.StatusNotFound,
		Error:   err.Error(),
		Success: false,
		Payload: nil})
}

func (writer *ResponseWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	writer.logError(r, err)
	writer.Write(w, r, http.StatusBadRequest, WebServiceResponse{
		Code:    http.StatusBadRequest,
		Error:   err.Error(),
		Success: false,
		Payload: payload})
}

func (writer *ResponseWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	writer.logError(r, err)
	writer.Write(w, r, http.StatusInternalServerError, WebServiceResponse{
		Code:    http.StatusInternalServerError,
		Error:   err.Error(),
		Success: false,
		Payload: nil})
}

func (writer *ResponseWriter) logResponse(w http.ResponseWriter, status int, response interface{}) {
	writer.logger.Debugf("header: %s, status: %d, response: %s",
		w.Header(), status, response)
}

func (writer *ResponseWriter) logRequest(r *http.Request) {
	if writer.session != nil {
		writer.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s, session: %+v",
			r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI, writer.session)
	} else {
		writer.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
			r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)
	}
}

func (writer *ResponseWriter) logError(r *http.Request, err error) {
	if writer.session != nil {
		writer.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s, session: %+v, error: %s",
			r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI, writer.session, err)
	} else {
		writer.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s, error: %s",
			r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI, err)
	}
}
