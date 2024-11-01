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
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	baseURI   string
	ca        ca.CertificateAuthority
	closeChan chan bool
	config    *config.WebService
	// endpointList        []string
	eventType           string
	httpServer          *http.Server
	logger              *logging.Logger
	middleware          middleware.JsonWebTokenMiddleware
	restServiceRegistry rest.RestServiceRegistry
	router              *mux.Router
	routerMutex         *sync.Mutex
	keyAttributes       *keystore.KeyAttributes
}

func NewWebServerV1(
	logger *logging.Logger,
	_ca ca.CertificateAuthority,
	config *config.WebService,
	restServiceRegistry rest.RestServiceRegistry,
	keyAttributes *keystore.KeyAttributes) *WebServerV1 {

	if _ca == nil {
		logger.FatalError(ca.ErrNotInitialized)
	}

	webserver := &WebServerV1{
		baseURI:   "/api/v1",
		ca:        _ca,
		closeChan: make(chan bool, 1),
		config:    config,
		// endpointList:        make([]string, 0),
		eventType:           "WebServer",
		logger:              logger,
		middleware:          restServiceRegistry.JsonWebTokenService(),
		restServiceRegistry: restServiceRegistry,
		router:              mux.NewRouter().StrictSlash(true),
		routerMutex:         &sync.Mutex{},
		keyAttributes:       keyAttributes,
	}

	webserver.httpServer = &http.Server{
		Handler:      webserver.router,
		IdleTimeout:  HTTP_SERVER_IDLE_TIMEOUT,
		ReadTimeout:  HTTP_SERVER_READ_TIMEOUT,
		WriteTimeout: HTTP_SERVER_WRITE_TIMEOUT,
	}
	return webserver
}

func (server WebServerV1) Router() *mux.Router {
	return server.router
}

func (server *WebServerV1) Run() {

	server.buildRoutes()

	// r := http.FileServer(http.Dir(server.config.Home))
	// server.router.PathPrefix("/").Handler(fs)
	// http.Handle("/", server.httpServer.Handler)
	server.router.PathPrefix("/").HandlerFunc(
		serveStaticFiles(server.config.Home, "index.html"))

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

func serveStaticFiles(staticDir string, indexFile string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		slog.Debug(r.URL.Path)

		path := filepath.Join(staticDir, r.URL.Path)
		if _, err := os.Stat(path); os.IsNotExist(err) {

			slog.Debug("file doesnt exist, serviing index.html")

			// If the file doesn't exist, serve index.html
			http.ServeFile(w, r, filepath.Join(staticDir, indexFile))
			return
		}

		slog.Debug("serving requested file", slog.String("path", path))

		// Otherwise, serve the static file
		http.ServeFile(w, r, path)
	}
}

func (server *WebServerV1) startHttp() {

	sWebPort := fmt.Sprintf(":%d", server.config.Port)
	ipv4Listener, err := net.Listen("tcp4", sWebPort)
	if err != nil {
		log.Fatal(err)
	}

	server.logger.Debugf("Listening for incoming HTTP web service connections on %s", sWebPort)

	err = server.httpServer.Serve(ipv4Listener)
	if err != nil {
		server.logger.Fatalf("webserver: unable to start web services: %s", err.Error())
	}
}

func (server *WebServerV1) startHttps() {

	sTlsAddr := fmt.Sprintf(":%d", server.config.TLSPort)
	server.logger.Debugf("webserver: starting secure TLS web services")

	// Retrieve a TLS config ready to go from the CA
	tlsconf, err := server.ca.TLSConfig(server.keyAttributes)
	if err != nil {
		server.logger.FatalError(err)
	}
	server.httpServer.TLSConfig = tlsconf

	// Create the TLS listener on the configured port
	tlsListener, err := tls.Listen("tcp4", sTlsAddr, tlsconf)
	if err != nil {
		server.logger.Fatalf("%s: %d", ErrBindPort, server.config.TLSPort)
	}

	if server.keyAttributes.Debug {
		bundle, err := server.ca.CABundle(&server.keyAttributes.StoreType, &server.keyAttributes.KeyAlgorithm)
		if err != nil {
			server.logger.FatalError(err)
		}
		fmt.Printf("TLS CA Bundle:\n%s\n", string(bundle))
	}

	server.logger.Debugf("Listening for incoming HTTPS web service connections on %s", sTlsAddr)

	// Start the http server and start serving requests
	err = server.httpServer.Serve(tlsListener)
	if err != nil {
		server.logger.Fatalf("Unable to start TLS web server: %s", err.Error())
	}
}

func (server *WebServerV1) buildRoutes() {

	muxRouter := mux.NewRouter().StrictSlash(true)
	responseWriter := response.NewResponseWriter(server.logger, nil)

	// Define CORS options
	corsOptions := middleware.CORSOptions{
		AllowedOrigins: []string{"http://localhost:3000"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"*"},
		// AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true, // Set to true if you need to allow cookies or other credentials
	}

	muxRouter.Use(middleware.CORSMiddleware(corsOptions))
	muxRouter.HandleFunc("/endpoints", server.endpoints)

	apiRouter := muxRouter.PathPrefix(server.baseURI).Subrouter()

	v1.NewRouter(
		server.logger,
		server.ca,
		server.keyAttributes,
		server.restServiceRegistry,
		responseWriter).RegisterRoutes(apiRouter)

	server.routerMutex.Lock()
	server.router = muxRouter
	server.httpServer.Handler = server.router
	server.routerMutex.Unlock()

	server.debugRoutes()
}

// @Summary REST API Endpoints
// @Description Returns a list of REST API endpoints
// @Tags System
// @Produce  json
// @Success 200
// @Router /endpoints [get]
func (server *WebServerV1) endpoints(w http.ResponseWriter, r *http.Request) {
	endpoints := make([]string, 0)
	server.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		t, err := route.GetPathTemplate()
		if err != nil {
			return err
		}
		endpoints = append(endpoints, t)
		return nil
	})
	responseWriter := response.NewResponseWriter(server.logger, nil)
	responseWriter.Write(w, r, http.StatusOK, endpoints)
}

func (server *WebServerV1) debugRoutes() {
	err := server.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		pathTemplate, err := route.GetPathTemplate()
		if err == nil {
			server.logger.Debug("ROUTE:", pathTemplate)
		}
		pathRegexp, err := route.GetPathRegexp()
		if err == nil {
			server.logger.Debug("Path regexp:", pathRegexp)
		}
		queriesTemplates, err := route.GetQueriesTemplates()
		if err == nil {
			server.logger.Debug("Queries templates:", strings.Join(queriesTemplates, ","))
		}
		queriesRegexps, err := route.GetQueriesRegexp()
		if err == nil {
			server.logger.Debug("Queries regexps:", strings.Join(queriesRegexps, ","))
		}
		methods, err := route.GetMethods()
		if err == nil {
			server.logger.Debug("Methods:", strings.Join(methods, ","))
		}
		server.logger.Debug("")
		return nil
	})
	if err != nil {
		server.logger.Errorf("[WebServer.WalkRoutes] Error: err", err)
	}
}
