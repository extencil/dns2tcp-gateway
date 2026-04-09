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
	"github.com/ohmymex/dns2tcp-gateway/internal/config"
	"github.com/ohmymex/dns2tcp-gateway/internal/dns"
	"github.com/ohmymex/dns2tcp-gateway/internal/session"
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

	logger.Info("starting dns2tcp gateway",
		"domain", cfg.Domain,
		"dns_addr", cfg.DNSAddr,
		"api_addr", cfg.APIAddr,
		"gateway_ip", cfg.GatewayIP,
	)

	// Shared session store, injected into both DNS and API servers.
	store := session.NewMemoryStore(logger)

	// Graceful shutdown context: cancelled on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start session cleanup goroutine.
	cleanupDone := store.StartCleanup(ctx, cfg.CleanupInterval)

	// Start DNS server.
	dnsServer := dns.New(cfg, store, logger)
	if err := dnsServer.Start(); err != nil {
		return fmt.Errorf("starting dns server: %w", err)
	}

	// Start API server (non-blocking).
	apiServer := api.New(cfg, store, logger)
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
