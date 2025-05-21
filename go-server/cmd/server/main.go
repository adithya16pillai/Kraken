package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourusername/secure-file-transfer-system/go-server/internal/api"
	"github.com/yourusername/secure-file-transfer-system/go-server/internal/config"
	"github.com/yourusername/secure-file-transfer-system/go-server/internal/storage"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger, err := config.SetupLogger(cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		log.Fatalf("Failed to setup logger: %v", err)
	}
	defer logger.Sync()

	// Initialize storage
	store, err := storage.NewStorage(cfg.Storage)
	if err != nil {
		logger.Fatal("Failed to initialize storage",
			"error", err,
		)
	}

	// Setup API server
	router := api.SetupRouter(cfg, store, logger)
	srv := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler: router,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("Starting server",
			"host", cfg.Server.Host,
			"port", cfg.Server.Port,
		)

		if cfg.Server.TLS.Enabled {
			if err := srv.ListenAndServeTLS(
				cfg.Server.TLS.CertFile,
				cfg.Server.TLS.KeyFile,
			); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to start server", "error", err)
			}
		} else {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Fatal("Failed to start server", "error", err)
			}
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", "error", err)
	}

	logger.Info("Server exiting")
}
