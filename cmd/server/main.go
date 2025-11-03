package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"authentio/internal/config"
	"authentio/internal/router"
	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
)

func main() {
	// Initialize Logger (use production mode based on env)
	if err := logger.InitLogger(true); err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("Starting Authentio service...")

	// Load config from env or config files
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("failed to load config", "error", err)
	}

	// Set Gin mode (release for prod, debug for dev)
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize router with dependencies
	r := router.NewRouter(cfg)

	// Create HTTP server
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.ServerPort),
		Handler: r,
	}

	// Run server in goroutine so we can gracefully shutdown
	go func() {
		logger.Info("Listening on port", "port", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logger.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	} else {
		logger.Info("Server exited gracefully")
	}
}
