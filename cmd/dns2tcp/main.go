package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ohmymex/dns2tcp-gateway/internal/api"
	"github.com/ohmymex/dns2tcp-gateway/internal/banner"
	"github.com/ohmymex/dns2tcp-gateway/internal/config"
	"github.com/ohmymex/dns2tcp-gateway/internal/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/relay"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
	"github.com/ohmymex/dns2tcp-gateway/internal/tunnel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Setup structured logger.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel(),
	}))
	slog.SetDefault(logger)

	// Load config from environment, falling back to defaults.
	cfg := loadConfig()
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Print startup banner to stderr (stdout is for structured logs).
	banner.Print(os.Stderr, cfg.Domain, cfg.DNSAddr, cfg.APIAddr)

	// Shared session store, injected into both DNS and API servers.
	store := session.NewMemoryStore(logger)

	// Tunnel manager handles dns2tcp protocol sessions.
	tunnelKey := os.Getenv("GATEWAY_TUNNEL_KEY")
	tunnelMgr := tunnel.NewManager(store, tunnelKey, logger)

	// RTCP relay manager for reverse TCP sessions.
	relayMgr := relay.NewManager(cfg.RTCPPortMin, cfg.RTCPPortMax, logger)

	// Graceful shutdown context: cancelled on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start session cleanup goroutine.
	cleanupDone := store.StartCleanup(ctx, cfg.CleanupInterval)

	// Start DNS server.
	dnsServer := dns.New(cfg, store, tunnelMgr, logger)
	if err := dnsServer.Start(); err != nil {
		return fmt.Errorf("starting dns server: %w", err)
	}

	// Start API server (non-blocking).
	apiServer := api.New(cfg, store, relayMgr, logger)
	apiErrCh := make(chan error, 1)
	go func() {
		apiErrCh <- apiServer.Start()
	}()

	// Wait for shutdown signal or fatal error.
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-apiErrCh:
		if err != nil {
			return fmt.Errorf("api server error: %w", err)
		}
	}

	// Graceful shutdown with timeout.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger.Info("shutting down servers")

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("api server shutdown error", "error", err)
	}
	if err := dnsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("dns server shutdown error", "error", err)
	}

	tunnelMgr.Shutdown()
	relayMgr.Shutdown()

	// Wait for cleanup goroutine to finish.
	<-cleanupDone

	logger.Info("dns2tcp gateway stopped")
	return nil
}

func loadConfig() config.Config {
	cfg := config.Default()

	if v := os.Getenv("GATEWAY_DOMAIN"); v != "" {
		cfg.Domain = v
	}
	if v := os.Getenv("GATEWAY_DNS_ADDR"); v != "" {
		cfg.DNSAddr = v
	}
	if v := os.Getenv("GATEWAY_API_ADDR"); v != "" {
		cfg.APIAddr = v
	}
	if v := os.Getenv("GATEWAY_IP"); v != "" {
		cfg.GatewayIP = v
	}
	if v := os.Getenv("GATEWAY_ADMIN_CONTACT"); v != "" {
		cfg.AdminContact = v
	}

	return cfg
}

func logLevel() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
