package server

import (
	"context"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/qingwave/weave/docs"
	"github.com/qingwave/weave/pkg/authentication"
	"github.com/qingwave/weave/pkg/authentication/oauth"
	"github.com/qingwave/weave/pkg/common"
	"github.com/qingwave/weave/pkg/config"
	"github.com/qingwave/weave/pkg/controller"
	"github.com/qingwave/weave/pkg/middleware"
	"github.com/qingwave/weave/pkg/utils/request"
	"github.com/qingwave/weave/pkg/utils/set"
	"github.com/sirupsen/logrus"
)

func New(conf *config.Config, logger *logrus.Logger) (*Server, error) {
	jwtService := authentication.NewJWTService(conf.Server.JWTSecret)
	oauthManager := oauth.NewOAuthManager(conf.OAuthConfig)

	authController := controller.NewAuthController(jwtService, oauthManager)
	controllers := []controller.Controller{authController}

	gin.SetMode(conf.Server.ENV)

	e := gin.New()
	e.Use(
		gin.Recovery(),
		middleware.MonitorMiddleware(),
		middleware.CORSMiddleware(),
		middleware.RequestInfoMiddleware(&request.RequestInfoFactory{APIPrefixes: set.NewString("api")}),
		middleware.LogMiddleware(logger, "/"),
		middleware.TraceMiddleware(),
	)

	e.LoadHTMLFiles("static/terminal.html")

	return &Server{
		engine:      e,
		config:      conf,
		logger:      logger,
		controllers: controllers,
	}, nil
}

type Server struct {
	engine *gin.Engine
	config *config.Config
	logger *logrus.Logger

	controllers []controller.Controller
}

// Run graceful shutdown
func (s *Server) Run() error {
	defer s.Close()

	s.initRouter()

	addr := fmt.Sprintf("%s:%d", s.config.Server.Address, s.config.Server.Port)
	s.logger.Infof("Start server on: %s", addr)

	server := &http.Server{
		Addr:    addr,
		Handler: s.engine,
	}

	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			s.logger.Fatalf("Failed to start server, %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.Server.GracefulShutdownPeriod)*time.Second)
	defer cancel()

	ch := <-sig
	s.logger.Infof("Receive signal: %s", ch)

	return server.Shutdown(ctx)
}

func (s *Server) Close() {
}

func (s *Server) initRouter() {
	root := s.engine

	// register non-resource routers
	root.GET("/", common.WrapFunc(s.getRoutes))
	root.GET("/index", controller.Index)

	api := root.Group("/api/v1")
	controllers := make([]string, 0, len(s.controllers))
	for _, router := range s.controllers {
		router.RegisterRoute(api)
		controllers = append(controllers, router.Name())
	}
	logrus.Infof("server enabled controllers: %v", controllers)
}

func (s *Server) getRoutes() []string {
	paths := set.NewString()
	for _, r := range s.engine.Routes() {
		if r.Path != "" {
			paths.Insert(r.Path)
		}
	}
	return paths.Slice()
}

type Status struct {
	Ping         bool `json:"ping"`
	DBRepository bool `json:"dbRepository"`
}

func (s *Server) Ping() *Status {
	return &Status{Ping: true}
}
