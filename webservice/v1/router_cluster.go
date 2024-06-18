//go:build cluster
// +build cluster

package v1

import (
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/cluster"
	"github.com/jeremyhahn/go-trusted-platform/mapper"
	"github.com/jeremyhahn/go-trusted-platform/service"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/rest"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/router"
)

type ClusterRouterV1 struct {
	raftNode cluster.RaftNode
	routerV1 RouterV1
	router.WebServiceRouter
}

func NewClusterRouterV1(
	app *app.App,
	raftNode cluster.RaftNode,
	mapperRegistry mapper.MapperRegistry,
	clusterServiceRegistry service.ClusterServiceRegistry,
	restServiceRegistry rest.RestServiceRegistry,
	farmWebSocketRestService rest.FarmWebSocketRestServicer,
	router *mux.Router,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &ClusterRouterV1{
		raftNode: raftNode,
		routerV1: RouterV1{
			app:                      app,
			mapperRegistry:           mapperRegistry,
			serviceRegistry:          clusterServiceRegistry,
			farmWebSocketRestService: farmWebSocketRestService,
			router:                   router,
			responseWriter:           responseWriter,
			endpointList:             make([]string, 0)}}
}

func (clusterRouterV1 *ClusterRouterV1) RegisterRoutes(router *mux.Router, baseURI string) []string {
	endpoints := clusterRouterV1.routerV1.registerNonClusterRoutes(router, baseURI)
	endpoints = append(endpoints, clusterRouterV1.systemRoutes()...)
	endpoints = append(endpoints, clusterRouterV1.raftRoutes()...)
	endpoints = clusterRouterV1.routerV1.sortAndDeDupe(endpoints)
	clusterRouterV1.routerV1.app.Logger.Debug(strings.Join(endpoints[:], "\n"))
	clusterRouterV1.routerV1.app.Logger.Debugf("Loaded %d REST endpoints", len(endpoints))
	clusterRouterV1.routerV1.endpointList = endpoints
	return endpoints
}

func (clusterRouterV1 *ClusterRouterV1) systemRoutes() []string {
	systemRouter := router.NewClusterSystemRouter(
		clusterRouterV1.routerV1.app,
		clusterRouterV1.routerV1.serviceRegistry.(service.ClusterServiceRegistry),
		clusterRouterV1.routerV1.jsonWebTokenMiddleware,
		clusterRouterV1.routerV1.router,
		clusterRouterV1.routerV1.responseWriter,
		&clusterRouterV1.routerV1.endpointList)
	return systemRouter.RegisterRoutes(clusterRouterV1.routerV1.router, clusterRouterV1.routerV1.baseURI)
}

func (clusterRouterV1 *ClusterRouterV1) raftRoutes() []string {
	orgRouter := router.NewRaftRouter(
		clusterRouterV1.routerV1.app.Logger,
		clusterRouterV1.raftNode,
		clusterRouterV1.routerV1.jsonWebTokenMiddleware,
		clusterRouterV1.routerV1.responseWriter)
	return orgRouter.RegisterRoutes(clusterRouterV1.routerV1.router, clusterRouterV1.routerV1.baseFarmURI)
}
