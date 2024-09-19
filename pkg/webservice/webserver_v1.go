// @title Trusted Platform
// @version v0.0.1
// @description The Trusted Platform RESTful Web Services API
// @termsOfService https://www.trusted-platform.io/terms

// @contact.name API Support
// @contact.url https://www.trusted-platform.io/support
// @contact.email support@trusted-platform.io

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
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

const (
	HTTP_CLIENT_TIMEOUT       = 10 * time.Second
	HTTP_SERVER_READ_TIMEOUT  = 5 * time.Second
	HTTP_SERVER_WRITE_TIMEOUT = 30 * time.Second //10 * time.Second
	HTTP_SERVER_IDLE_TIMEOUT  = 120 * time.Second
)

var (
	ErrLoadTlsCerts = errors.New("webserver: unable to load TLS certificates")
	ErrBindPort     = errors.New("webserver: unable to bind to web service port")
)

type WebServerV1 struct {
	baseURI             string
	ca                  ca.CertificateAuthority
	closeChan           chan bool
	config              *config.WebService
	endpointList        []string
	eventType           string
	httpServer          *http.Server
	listenAddress       string
	logger              *logging.Logger
	middleware          middleware.JsonWebTokenMiddleware
	restServiceRegistry rest.RestServiceRegistry
	router              *mux.Router
	routerMutex         *sync.Mutex
	serverKeyAttributes *keystore.KeyAttributes
}

func NewWebServerV1(
	logger *logging.Logger,
	_ca ca.CertificateAuthority,
	config *config.WebService,
	listenAddress string,
	restServiceRegistry rest.RestServiceRegistry,
	serverKeyAttributes *keystore.KeyAttributes) *WebServerV1 {

	if _ca == nil {
		logger.FatalError(ca.ErrNotInitialized)
	}

	webserver := &WebServerV1{
		baseURI:             "/api/v1",
		ca:                  _ca,
		closeChan:           make(chan bool, 1),
		config:              config,
		endpointList:        make([]string, 0),
		eventType:           "WebServer",
		logger:              logger,
		middleware:          restServiceRegistry.JsonWebTokenService(),
		restServiceRegistry: restServiceRegistry,
		router:              mux.NewRouter().StrictSlash(true),
		routerMutex:         &sync.Mutex{},
		serverKeyAttributes: serverKeyAttributes,
	}

	webserver.httpServer = &http.Server{
		Handler:      webserver.router,
		IdleTimeout:  HTTP_SERVER_IDLE_TIMEOUT,
		ReadTimeout:  HTTP_SERVER_READ_TIMEOUT,
		WriteTimeout: HTTP_SERVER_WRITE_TIMEOUT,
	}
	return webserver
}

func (server *WebServerV1) Run() {

	server.buildRoutes()

	fs := http.FileServer(http.Dir(server.config.Home))
	server.router.PathPrefix("/").Handler(fs)
	http.Handle("/", server.httpServer.Handler)

	if server.config.TLSPort > 0 {
		go server.startHttps()
	} else {
		go server.startHttp()
	}
	go server.startHttp()

	<-server.closeChan
}

func (server WebServerV1) Shutdown() {
	server.logger.Info("webserver: shutting down")
	server.closeChan <- true
	close(server.closeChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	server.httpServer.Shutdown(ctx)
	cancel()
}

func (server *WebServerV1) startHttp() {

	sWebPort := fmt.Sprintf(":%d", server.config.Port)

	insecureWebServicesMsg := fmt.Sprintf(
		"webserver: starting insecure web services on plain-text HTTP port %s", sWebPort)
	server.logger.Infof(insecureWebServicesMsg)

	ipv4Listener, err := net.Listen("tcp4", sWebPort)
	if err != nil {
		log.Fatal(err)
	}

	err = server.httpServer.Serve(ipv4Listener)
	if err != nil {
		server.logger.Fatalf("webserver: unable to start web services: %s", err.Error())
	}
}

func (server *WebServerV1) startHttps() {

	sTlsAddr := fmt.Sprintf("%s:%d", server.listenAddress, server.config.TLSPort)
	message := fmt.Sprintf("webserver: starting secure TLS web services on %s", sTlsAddr)
	server.logger.Debugf(message)

	// Retrieve a TLS config ready to go from the CA
	tlsconf, err := server.ca.TLSConfig(server.serverKeyAttributes)
	if err != nil {
		server.logger.FatalError(err)
	}
	// if !keystore.IsRSAPSS(server.serverKeyAttributes.SignatureAlgorithm) {
	// w, err := os.OpenFile("key.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	// if err != nil {
	// 	fmt.Printf("failed to open file err %+v", err)
	// 	return
	// }
	// 	server.logger.Warn("using TLS v1.2")
	// 	tlsconf.MaxVersion = tls.VersionTLS12
	// 	tlsconf.MinVersion = tls.VersionTLS12
	// 	tlsconf.KeyLogWriter = w
	// 	tlsconf.Certificates[0].SupportedSignatureAlgorithms = []tls.SignatureScheme{
	// 		// tls.PKCS1WithSHA1,
	// 		tls.PKCS1WithSHA256,
	// 		tls.PKCS1WithSHA384,
	// 		tls.PKCS1WithSHA512,
	// 		tls.ECDSAWithP256AndSHA256,
	// 		tls.ECDSAWithP384AndSHA384,
	// 		tls.ECDSAWithP521AndSHA512,
	// 		tls.Ed25519,
	// 	}
	// 	// opaque, err := server.ca.Keyring().Key(server.serverKeyAttributes)
	// 	// if err != nil {
	// 	// 	server.logger.Error(err)
	// 	// 	return
	// 	// }
	// 	// tlsconf.Certificates[0].PrivateKey = opaque
	// }
	server.httpServer.TLSConfig = tlsconf

	// Create the TLS listener on the configured port
	tlsListener, err := tls.Listen("tcp4", sTlsAddr, tlsconf)
	if err != nil {
		server.logger.Fatalf("%s: %d", ErrBindPort, server.config.TLSPort)
	}

	server.logger.Debugf("Lsitening for incoming web service connections on %s", sTlsAddr)

	// Start the http server and start serving requests
	err = server.httpServer.Serve(tlsListener)
	if err != nil {
		server.logger.Fatalf("Unable to start TLS web server: %s", err.Error())
	}
}

func (server *WebServerV1) buildRoutes() {
	muxRouter := mux.NewRouter().StrictSlash(true)
	responseWriter := response.NewResponseWriter(server.logger, nil)
	endpointList := v1.NewRouterV1(
		server.logger,
		server.ca,
		server.serverKeyAttributes,
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
// 			server.logger.Debug("ROUTE:", pathTemplate)
// 		}
// 		pathRegexp, err := route.GetPathRegexp()
// 		if err == nil {
// 			server.logger.Debug("Path regexp:", pathRegexp)
// 		}
// 		queriesTemplates, err := route.GetQueriesTemplates()
// 		if err == nil {
// 			server.logger.Debug("Queries templates:", strings.Join(queriesTemplates, ","))
// 		}
// 		queriesRegexps, err := route.GetQueriesRegexp()
// 		if err == nil {
// 			server.logger.Debug("Queries regexps:", strings.Join(queriesRegexps, ","))
// 		}
// 		methods, err := route.GetMethods()
// 		if err == nil {
// 			server.logger.Debug("Methods:", strings.Join(methods, ","))
// 		}
// 		server.logger.Debug("")
// 		return nil
// 	})
// 	if err != nil {
// 		server.logger.Errorf("[WebServer.WalkRoutes] Error: err", err)
// 	}
// }
