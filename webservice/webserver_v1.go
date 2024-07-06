// @title Trusted Platform
// @version v0.0.1
// @description This is the RESTful Web Services API for Trusted Platform
// @termsOfService https://www.trusted-platform.io/terms

// @contact.name API Support
// @contact.url https://www.trusted-platform.io/support
// @contact.email support@trusted-platform.org

// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.txt

// @license.name Commercial
// @license.url https://www.trusted-platform.io/licenses/commercial.txt

// @host localhost:8443
// @BasePath /api/v1
// schemes: [http, https, ws, wss]
// @securityDefinitions.apikey JWT
// @in header
// @name Authorization

package webservice

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/config"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/rest"

	v1 "github.com/jeremyhahn/go-trusted-platform/webservice/v1"
)

const (
	HTTP_CLIENT_TIMEOUT       = 10 * time.Second
	HTTP_SERVER_READ_TIMEOUT  = 5 * time.Second
	HTTP_SERVER_WRITE_TIMEOUT = 30 * time.Second //10 * time.Second
	HTTP_SERVER_IDLE_TIMEOUT  = 120 * time.Second
	HTTP_PUBLIC_HTML          = "public_html"
)

var (
	ErrLoadTlsCerts = errors.New("webserver: unable to load TLS certificates")
	ErrBindPort     = errors.New("webserver: unable to bind to web service port")
)

type WebServerV1 struct {
	app                 *app.App
	config              config.WebService
	baseURI             string
	eventType           string
	endpointList        []string
	routerMutex         *sync.Mutex
	router              *mux.Router
	httpServer          *http.Server
	restServiceRegistry rest.RestServiceRegistry
	middleware          middleware.JsonWebTokenMiddleware
	password            []byte
	closeChan           chan bool
}

func NewWebServerV1(
	app *app.App,
	password []byte,
	restServiceRegistry rest.RestServiceRegistry) *WebServerV1 {

	webserver := &WebServerV1{
		app:                 app,
		password:            password,
		baseURI:             "/api/v1",
		eventType:           "WebServer",
		endpointList:        make([]string, 0),
		routerMutex:         &sync.Mutex{},
		router:              mux.NewRouter().StrictSlash(true),
		restServiceRegistry: restServiceRegistry,
		middleware:          restServiceRegistry.JsonWebTokenService(),
		closeChan:           make(chan bool, 1)}

	webserver.httpServer = &http.Server{
		ReadTimeout:  HTTP_SERVER_READ_TIMEOUT,
		WriteTimeout: HTTP_SERVER_WRITE_TIMEOUT,
		IdleTimeout:  HTTP_SERVER_IDLE_TIMEOUT,
		Handler:      webserver.router}

	return webserver
}

func (server *WebServerV1) Run() {

	server.buildRoutes()

	fs := http.FileServer(http.Dir(HTTP_PUBLIC_HTML))
	server.router.PathPrefix("/").Handler(fs)
	http.Handle("/", server.httpServer.Handler)

	if server.app.WebService.TLSPort > 0 {
		go server.startHttps()
	} else {
		go server.startHttp()
	}

	server.app.DropPrivileges()

	<-server.closeChan
}

func (server WebServerV1) Shutdown() {
	server.app.Logger.Info("webserver: shutting down")
	server.closeChan <- true
	close(server.closeChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	server.httpServer.Shutdown(ctx)
	cancel()
}

func (server *WebServerV1) startHttp() {

	sWebPort := fmt.Sprintf(":%d", server.app.WebService.Port)

	insecureWebServicesMsg := fmt.Sprintf(
		"webserver: starting insecure web services on plain-text HTTP port %s", sWebPort)
	server.app.Logger.Infof(insecureWebServicesMsg)

	ipv4Listener, err := net.Listen("tcp4", sWebPort)
	if err != nil {
		log.Fatal(err)
	}

	//err = http.Serve(ipv4Listener, server.router)
	err = server.httpServer.Serve(ipv4Listener)
	if err != nil {
		server.app.Logger.Fatalf("webserver: unable to start web services: %s", err.Error())
	}
}

func (server *WebServerV1) startHttps() {

	sTlsPort := fmt.Sprintf(":%d", server.app.WebService.TLSPort)
	message := fmt.Sprintf("webserver: starting secure web services on TLS port %s", sTlsPort)
	server.app.Logger.Debugf(message)

	// Retrieve a TLS config ready to go from the CA
	tlsconf, err := server.app.CA.TLSConfig(
		server.app.Domain,
		server.app.Domain,
		server.password,
		false)
	if err != nil {
		server.app.Logger.Fatal(err)
	}
	server.httpServer.TLSConfig = tlsconf

	// Create the TLS listener on the configured port
	tlsListener, err := tls.Listen("tcp4", sTlsPort, tlsconf)
	if err != nil {
		server.app.Logger.Fatalf("%s: %d", ErrBindPort, server.app.WebService.TLSPort)
	}

	// Start the http server and start serving requests
	err = server.httpServer.Serve(tlsListener)
	if err != nil {
		server.app.Logger.Fatalf("Unable to start TLS web server: %s", err.Error())
	}
}

func (server *WebServerV1) buildRoutes() {
	muxRouter := mux.NewRouter().StrictSlash(true)
	responseWriter := response.NewResponseWriter(server.app.Logger, nil)
	endpointList := v1.NewRouterV1(
		server.app,
		server.restServiceRegistry,
		muxRouter,
		responseWriter).RegisterRoutes(muxRouter, server.baseURI)
	server.routerMutex.Lock()
	server.router = muxRouter
	copy(server.endpointList, endpointList)
	server.httpServer.Handler = server.router
	server.routerMutex.Unlock()
}

// func (server *WebServer) walkRoutes() {
// 	err := server.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
// 		pathTemplate, err := route.GetPathTemplate()
// 		if err == nil {
// 			server.app.Logger.Debug("ROUTE:", pathTemplate)
// 		}
// 		pathRegexp, err := route.GetPathRegexp()
// 		if err == nil {
// 			server.app.Logger.Debug("Path regexp:", pathRegexp)
// 		}
// 		queriesTemplates, err := route.GetQueriesTemplates()
// 		if err == nil {
// 			server.app.Logger.Debug("Queries templates:", strings.Join(queriesTemplates, ","))
// 		}
// 		queriesRegexps, err := route.GetQueriesRegexp()
// 		if err == nil {
// 			server.app.Logger.Debug("Queries regexps:", strings.Join(queriesRegexps, ","))
// 		}
// 		methods, err := route.GetMethods()
// 		if err == nil {
// 			server.app.Logger.Debug("Methods:", strings.Join(methods, ","))
// 		}
// 		server.app.Logger.Debug("")
// 		return nil
// 	})
// 	if err != nil {
// 		server.app.Logger.Errorf("[WebServer.WalkRoutes] Error: err", err)
// 	}
// }
