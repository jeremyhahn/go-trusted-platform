// @title Trusted Platform
// @version 0.0.4-alpha.1
// @description The Trusted Platform RESTful Web Services API
// @termsOfService https://www.trusted-platform.io/terms

// @contact.name API Support
// @contact.url https://www.trusted-platform.io/support
// @contact.email support@trusted-platform.io

// @license.name Apache 2.0
// @license.url https://www.apache.org/licenses/LICENSE-2.0.txt

// @license.name Commercial
// @license.url https://www.trusted-platform.io/licenses/commercial.txt

// @host trusted-platform.io
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
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
)

const (
	HTTP_CLIENT_TIMEOUT       = 10 * time.Second
	HTTP_SERVER_READ_TIMEOUT  = 5 * time.Second
	HTTP_SERVER_WRITE_TIMEOUT = 30 * time.Second
	HTTP_SERVER_IDLE_TIMEOUT  = 120 * time.Second

	defaultIndexTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>Welcome</title>
</head>
<body>
    <h1>Welcome to {{.VirtualHost}}</h1>
</body>
</html>`
)

var (
	ErrLoadTlsCerts = errors.New("webserver: unable to load TLS certificates")
	ErrBindPort     = errors.New("webserver: unable to bind to web service port")
)

type WebServerV1 struct {
	baseURI             string
	ca                  ca.CertificateAuthority
	closeChan           chan bool
	config              *v1.Config
	debug               bool
	eventType           string
	httpServer          *http.Server
	logger              *logging.Logger
	middleware          middleware.JsonWebTokenMiddleware
	restServiceRegistry v1.RestHandlerRegistry
	router              *mux.Router
	routerMutex         *sync.Mutex
	keyAttributes       *keystore.KeyAttributes
}

func NewWebServerV1(
	debug bool,
	logger *logging.Logger,
	_ca ca.CertificateAuthority,
	config *v1.Config,
	restServiceRegistry v1.RestHandlerRegistry,
	keyAttributes *keystore.KeyAttributes) *WebServerV1 {

	if _ca == nil {
		logger.FatalError(ca.ErrNotInitialized)
	}

	webserver := &WebServerV1{
		baseURI:             "/api/v1",
		ca:                  _ca,
		closeChan:           make(chan bool, 1),
		config:              config,
		debug:               debug,
		eventType:           "WebServer",
		logger:              logger,
		middleware:          restServiceRegistry.JSONWebTokenHandler(),
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

// Shutdown the web server
func (server *WebServerV1) Shutdown() {
	server.logger.Info("webserver: shutting down")
	server.closeChan <- true
	close(server.closeChan)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	server.httpServer.Shutdown(ctx)
	cancel()
}

// Starts the web server
func (server *WebServerV1) Run() {
	server.buildRoutes()

	if server.config.VirtualHosts != nil {
		for _, vhost := range *server.config.VirtualHosts {
			// Create the virtual host directory
			vhostDir := filepath.Join(server.config.Home, vhost.Home)

			// Use the virtual host's custom index or fallback to the global index
			indexFile := vhost.Index
			if indexFile == "" {
				indexFile = server.config.Index
			}

			// Ensure the directory exists
			if err := server.ensureDirectoryExists(vhostDir, vhost.Hosts[0], indexFile); err != nil {
				server.logger.Errorf("Failed to set up directory for virtual host %s: %v", vhost.Hosts[0], err)
				continue
			}

			// Configure CORS middleware
			var corsMiddleware func(http.Handler) http.Handler
			if vhost.CORS != nil {
				corsMiddleware = middleware.CORSMiddleware(middleware.CORSOptions{
					AllowedOrigins:   vhost.CORS.AllowedOrigins,
					AllowedMethods:   vhost.CORS.AllowedMethods,
					AllowedHeaders:   vhost.CORS.AllowedHeaders,
					AllowCredentials: vhost.CORS.AllowCredentials,
				})
			}

			// Map each host header to the resolved directory
			for _, host := range vhost.Hosts {
				subRouter := server.router.Host(host).Subrouter()
				if corsMiddleware != nil {
					subRouter.Use(corsMiddleware)
				}

				if vhost.Proxy != nil && len(vhost.Proxy.Backends) > 0 {
					subRouter.PathPrefix("/").HandlerFunc(
						server.reverseProxyHandler(vhost.Proxy.Backends, RoundRobinBalancer()),
					)
					server.logger.Infof("Virtual host %s configured as reverse proxy", host)
				} else {
					subRouter.PathPrefix("/").HandlerFunc(
						server.serveStaticFiles(vhostDir, indexFile, vhost.RewriteRules),
					)
					server.logger.Infof("Virtual host %s mapped to directory %s with index %s", host, vhostDir, indexFile)
				}
			}
		}
	}

	// Apply global CORS middleware
	server.router.Use(middleware.CORSMiddleware(middleware.CORSOptions{
		AllowedOrigins:   server.config.CORS.AllowedOrigins,
		AllowedMethods:   server.config.CORS.AllowedMethods,
		AllowedHeaders:   server.config.CORS.AllowedHeaders,
		AllowCredentials: server.config.CORS.AllowCredentials,
	}))

	// Default handler for unmatched routes
	server.router.PathPrefix("/").HandlerFunc(
		server.serveStaticFiles(server.config.Home, server.config.Index, server.config.RewriteRules),
	)

	// Start HTTP / HTTPS servers
	if server.config.TLSPort > 0 {
		go server.startHTTPS()
	}
	go server.startHTTP()

	<-server.closeChan
}

// Serve static files from the provided directory with optional rewrite rules
func (server *WebServerV1) serveStaticFiles(rootDir, index string, rewriteRules []*v1.RewriteRule) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestPath := filepath.Clean(r.URL.Path)
		server.logger.Debug("Incoming request",
			slog.String("requestPath", requestPath),
		)

		// Apply rewrite rules
		for _, rule := range rewriteRules {
			matched, err := regexp.MatchString(rule.Pattern, requestPath)
			if err != nil {
				server.logger.Error(errors.New("Invalid rewrite pattern"),
					slog.String("pattern", rule.Pattern),
					slog.Any("error", err),
				)
				continue
			}
			if matched {
				server.logger.Debug("Rewrite applied",
					slog.String("originalPath", requestPath),
					slog.String("rewrittenPath", rule.Target),
					slog.String("pattern", rule.Pattern),
				)
				requestPath = rule.Target
				break
			}
		}

		// Resolve static file path
		staticPath := filepath.Join(rootDir, requestPath)
		server.logger.Debug("Resolved static path",
			slog.String("staticPath", staticPath),
		)

		info, err := os.Stat(staticPath)
		if err == nil {
			// Serve file directly if it exists
			if !info.IsDir() {
				server.logger.Debug("Serving static file",
					slog.String("filePath", staticPath),
				)
				http.ServeFile(w, r, staticPath)
				return
			}
			// Serve the index file if the request points to a directory
			staticPath = filepath.Join(staticPath, index)
			if _, err := os.Stat(staticPath); err == nil {
				server.logger.Debug("Serving directory index file",
					slog.String("filePath", staticPath),
				)
				http.ServeFile(w, r, staticPath)
				return
			}
		}

		// Only fallback to index.html for SPA routes, not static resources
		if strings.HasPrefix(requestPath, "/_next/") || strings.HasPrefix(requestPath, "/static/") {
			server.logger.Warn("Static resource not found",
				slog.String("requestPath", requestPath),
			)
			http.NotFound(w, r)
			return
		}

		// Fallback to SPA index
		fallbackPath := filepath.Join(rootDir, index)
		server.logger.Debug("Fallback to SPA index file",
			slog.String("fallbackPath", fallbackPath),
			slog.String("requestedPath", requestPath),
		)

		if _, err := os.Stat(fallbackPath); err == nil {
			server.logger.Debug("Serving SPA index file",
				slog.String("filePath", fallbackPath),
			)
			http.ServeFile(w, r, fallbackPath)
			return
		}

		// File not found
		server.logger.Warn("File not found",
			slog.String("staticPath", staticPath),
			slog.String("requestedPath", requestPath),
		)
		http.NotFound(w, r)
	}
}

// Ensures the provided directory exists and creates it with the specified index file
// if it doesn't exist.
func (server *WebServerV1) ensureDirectoryExists(vhostDir, virtualHost, index string) error {

	// Create directory if it does not exist
	if err := os.MkdirAll(vhostDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", vhostDir, err)
	}

	// Create default index file
	if err := server.createDefaultIndexFile(vhostDir, virtualHost, index); err != nil {
		return fmt.Errorf("failed to create default index file in directory %s: %w", vhostDir, err)
	}

	return nil
}

// Creates a default index file in the provided directory if it doesn't exist.
func (server *WebServerV1) createDefaultIndexFile(directory, virtualHost, index string) error {
	indexFilePath := filepath.Join(directory, index)

	// Skip creation if file already exists
	if _, err := os.Stat(indexFilePath); err == nil {
		server.logger.Warn("Index file already exists",
			slog.String("index", indexFilePath))
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check index file: %w", err)
	}

	// Create and write default index file
	tmpl, err := template.New("index").Parse(defaultIndexTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse default index template: %w", err)
	}

	file, err := os.Create(indexFilePath)
	if err != nil {
		return fmt.Errorf("failed to create index file: %w", err)
	}
	defer file.Close()

	// Fill template data and write file
	data := struct{ VirtualHost string }{VirtualHost: virtualHost}
	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to write to index file: %w", err)
	}

	server.logger.Info(
		"Created default index file",
		slog.String("virtualhost", virtualHost),
		slog.String("index", indexFilePath))
	return nil
}

// Validates the provided host header to prevent injection attacks.
func (server *WebServerV1) validateHostHeader(host string) bool {
	const domainPattern = `^(localhost|([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(:[0-9]{1,5})?$`

	// Check if it's a valid domain name with an optional port
	if matched, _ := regexp.MatchString(domainPattern, host); matched {
		return true
	}

	// Split the host and port if present
	hostWithoutPort, _, err := net.SplitHostPort(host)
	if err != nil {
		// If splitting fails, assume the entire host might be an IP
		hostWithoutPort = host
	}

	// Check if it's a valid IP address (IPv4 or IPv6)
	if net.ParseIP(hostWithoutPort) != nil {
		return true
	}

	// Host header is invalid
	return false
}

// Handler for reverse proxying requests to a list of backend servers
func (server *WebServerV1) reverseProxyHandler(backends []string, lbFunc LoadBalancerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if len(backends) == 0 {
			http.Error(w, "No backend servers configured", http.StatusInternalServerError)
			return
		}

		// Select a backend using the load balancer
		backend := lbFunc(backends)
		backendURL, err := url.Parse(backend)
		if err != nil {
			server.logger.Errorf("Invalid backend URL: %s, error: %v", backend, err)
			http.Error(w, "Invalid backend URL", http.StatusInternalServerError)
			return
		}

		// Proxy the request to the selected backend
		proxy := httputil.NewSingleHostReverseProxy(backendURL)
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
			server.logger.Errorf("Proxy error: %v", e)
			http.Error(w, "Proxy error", http.StatusBadGateway)
		}
		server.logger.Debug("Proxying request to backend",
			slog.String("backend", backendURL.String()),
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method),
			slog.String("remote-addr", r.RemoteAddr),
			slog.String("host", r.Host),
		)
		proxy.ServeHTTP(w, r)
	}
}

// Start the HTTP server (HTTP/1.1 and HTTP/2 only)
func (server *WebServerV1) startHTTP() {

	sWebAddr := fmt.Sprintf(":%d", server.config.Port)
	ipv4Listener, err := net.Listen("tcp4", sWebAddr)
	if err != nil {
		server.logger.Fatalf("Failed to start HTTP server: %v", err)
	}

	server.logger.Info(
		"Listening for incoming HTTP (HTTP/1.1, HTTP/2) connections",
		slog.String("tcp", sWebAddr))

	err = server.httpServer.Serve(ipv4Listener)
	if err != nil {
		server.logger.Fatalf("webserver: unable to start web services: %v", err)
	}
}

// Start the HTTPS server (HTTP/1.1, HTTP/2, and HTTP/3)
func (server *WebServerV1) startHTTPS() {

	sTlsAddr := fmt.Sprintf(":%d", server.config.TLSPort)

	server.logger.Info("starting secure TLS web services",
		slog.String("address", sTlsAddr))

	// Configure TLS for HTTP/1.1, HTTP/2, and HTTP/3
	var tlsconf *tls.Config
	var err error
	if server.config.Certificate.ACME != nil && server.config.Certificate.ACME.CrossSigner != nil {
		issuerCN, err := util.ParseFQDN(server.config.Certificate.ACME.CrossSigner.DirectoryURL)
		if err != nil {
			server.logger.FatalError(err)
		}
		tlsconf, err = server.ca.TLSConfigWithXSigner(server.keyAttributes, issuerCN)
	} else {
		tlsconf, err = server.ca.TLSConfig(server.keyAttributes)
	}
	if err != nil {
		server.logger.FatalError(err)
	}
	tlsconf.NextProtos = []string{"h3", "h2", "http/1.1"}
	server.httpServer.TLSConfig = tlsconf

	// Start HTTP/3 Server
	h3Server := &http3.Server{
		TLSConfig:  tlsconf,
		Handler:    server.httpServer.Handler, // Reuse the same HTTP handler
		QUICConfig: &quic.Config{},
	}

	// Listen for UDP traffic for HTTP/3
	udpConn, err := net.ListenPacket("udp", sTlsAddr)
	if err != nil {
		server.logger.Fatalf("Failed to start HTTP/3 server: %v", err)
	}

	go func() {
		server.logger.Info(
			"Listening for incoming HTTP/3 connections",
			slog.String("udp", sTlsAddr))

		if err := h3Server.Serve(udpConn); err != nil && err != http.ErrServerClosed {
			server.logger.Fatalf("HTTP/3 server error: %v", err)
		}
	}()

	// Start HTTPS server for HTTP/1.1 and HTTP/2
	tlsListener, err := tls.Listen("tcp", sTlsAddr, tlsconf)
	if err != nil {
		server.logger.Fatalf("Failed to start HTTPS server: %v", err)
	}

	server.logger.Info(
		"Listening for incoming HTTPS (HTTP/1.1, HTTP/2) connections",
		slog.String("tcp", sTlsAddr))

	if err := server.httpServer.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		server.logger.Fatalf("HTTPS server error: %v", err)
	}
}

// Build the routes for the web server. This is a thread safe operation that
// can be used to dynamically update the web server routes at runtime.
func (server *WebServerV1) buildRoutes() {

	responseWriter := response.NewResponseWriter(server.logger, nil)

	muxRouter := mux.NewRouter().StrictSlash(true)

	muxRouter.Use(middleware.CORSMiddleware(middleware.CORSOptions{
		AllowedOrigins:   server.config.CORS.AllowedOrigins,
		AllowedMethods:   server.config.CORS.AllowedMethods,
		AllowedHeaders:   server.config.CORS.AllowedHeaders,
		AllowCredentials: server.config.CORS.AllowCredentials,
	}))

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

	if server.debug {
		server.debugRoutes()
	}
}

// DebugRoutes prints the routes to the log
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
		server.logger.Errorf("[WebServer.WalkRoutes] Error: %v", err)
	}
}
