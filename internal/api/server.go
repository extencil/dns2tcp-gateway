package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/config"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
)

// Server is the REST API server for tunnel management.
type Server struct {
	http   *http.Server
	store  session.Store
	cfg    config.Config
	logger *slog.Logger
}

// New creates a new API server wired to the given session store and config.
func New(cfg config.Config, store session.Store, logger *slog.Logger) *Server {
	s := &Server{
		store:  store,
		cfg:    cfg,
		logger: logger.With("component", "api"),
	}

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.http = &http.Server{
		Addr:         cfg.APIAddr,
		Handler:      s.withMiddleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins serving HTTP requests. It blocks until the server stops.
func (s *Server) Start() error {
	s.logger.Info("api server listening", "addr", s.cfg.APIAddr)
	if err := s.http.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("api server: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the API server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/tcp/{ip}/{port}", s.handleCreateTCP)
	mux.HandleFunc("POST /v1/ns/{ip}/{port}", s.handleCreateNS)
	mux.HandleFunc("POST /v1/rtcp", s.handleCreateRTCP)
	mux.HandleFunc("GET /v1/status/{subdomain}", s.handleStatus)
	mux.HandleFunc("DELETE /v1/{subdomain}", s.handleDelete)
	mux.HandleFunc("GET /health", s.handleHealth)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return s.logMiddleware(next)
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.logger.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
