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
	"github.com/qingwave/weave/pkg/authentication"
	"github.com/qingwave/weave/pkg/config"
	"github.com/qingwave/weave/pkg/controller"
	"github.com/qingwave/weave/pkg/middleware"
	"github.com/qingwave/weave/pkg/utils/request"
	"github.com/qingwave/weave/pkg/utils/set"
	"github.com/sirupsen/logrus"
)

func New(conf *config.Config, logger *logrus.Logger) (*Server, error) {
	jwtService := authentication.NewJWTService(conf.Server.JWTSecret)

	authController := controller.NewAuthController(jwtService)
	gin.SetMode(conf.Server.ENV)

	e := gin.New()
	e.Use(
		gin.Recovery(),
		middleware.CORSMiddleware(),
		middleware.RequestInfoMiddleware(&request.RequestInfoFactory{APIPrefixes: set.NewString("api")}),
		middleware.LogMiddleware(logger, "/"),
	)

	e.LoadHTMLFiles("static/terminal.html")

	return &Server{
		engine: e,
		config: conf,
		logger: logger,
		auth:   authController,
	}, nil
}

type Server struct {
	engine *gin.Engine
	config *config.Config
	logger *logrus.Logger

	auth *controller.AuthController
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
	root.GET("/index", controller.Index)
	root.GET("/api/v1/auth/token", s.auth.GetToken)

	api := root.Group("/api/v1")
	controllers := make([]string, 0, 1)
	s.auth.RegisterRoute(api)
	controllers = append(controllers, s.auth.Name())
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
