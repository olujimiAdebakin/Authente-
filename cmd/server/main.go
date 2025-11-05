package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"authentio/internal/config"
	dbpkg "authentio/internal/database"
	"authentio/internal/handler"
	"authentio/internal/router"
	"authentio/internal/service"
	"authentio/pkg/email" 
	"authentio/pkg/jwt"
	"authentio/pkg/logger"
	
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	_ "github.com/jackc/pgx/v5/stdlib"

	// Swagger imports
	_ "authentio/docs" // This imports your generated docs
)

// @title Authentio API
// @version 1.0
// @description Secure authentication service with JWT, OAuth2, 2FA, and password reset functionality
// @termsOfService http://swagger.io/terms/

// @contact.name Authentio Support
// @contact.url https://authentio.com/support
// @contact.email support@authentio.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT Bearer token. Format: "Bearer {your_jwt_token}"

// @externalDocs.description  OpenAPI
// @externalDocs.url          https://swagger.io/resources/open-api/

// main is the entry point of the Authentio authentication service.
// It initializes configuration, logging, database connections, Redis, email client,
// JWT manager, repositories, services, handlers, and starts the HTTP server with graceful shutdown.
func main() {
	// Load configuration from environment or .env file
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	googleOAuthConfig := config.GoogleOAuthConfig

	// Initialize email client for sending OTPs and notifications
	emailClient := email.NewClient(
		cfg.SMTPHost,
		cfg.SMTPPort,
		cfg.SMTPUsername,
		cfg.SMTPPassword,
		cfg.SMTPFrom,
	)

	// Initialize structured logger (JSON in production, console in dev)
	if err := logger.InitLogger(cfg.Env == "production"); err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() // Ensure all logs are flushed on exit

	logger.Info("Starting Authentio service", "env", cfg.Env, "port", cfg.ServerPort)

	// Set Gin runtime mode
	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize PostgreSQL connection
	db, err := sql.Open("pgx", cfg.PostgresDSN)
	if err != nil {
		logger.Fatal("failed to open database connection", "error", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("error closing database", "error", err)
		}
	}()

	// Verify database connectivity
	ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelPing()
	if err := db.PingContext(ctxPing); err != nil {
		logger.Fatal("failed to ping database", "error", err)
	}
	logger.Info("Database connection established")

	// Initialize Redis client for rate limiting, caching, and session management
	redisClient := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPass,
		DB:       0, // uses default DB
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		logger.Fatal("failed to connect to Redis", "error", err)
	}
	logger.Info("Redis connection established")
	defer func() {
		if err := redisClient.Close(); err != nil {
			logger.Error("error closing Redis client", "error", err)
		}
	}()

	// Test email service (non-fatal in production, but warn)
	if err := emailClient.Send([]string{"test@example.com"}, "Authentio Email Test", "Email service is working!"); err != nil {
		logger.Warn("Email service test failed - check SMTP settings", "error", err)
	} else {
		logger.Info("Email service initialized and tested successfully")
	}

	// Initialize JWT manager for token signing and verification
	jwtManager := jwt.NewManager(cfg.JWTSecret)

	// Initialize data repositories
	userRepo := dbpkg.NewUserRepository(db)
	tokenRepo := dbpkg.NewTokenRepository(db)
	otpRepo := dbpkg.NewOTPRepository(db)
	twoFARepo := dbpkg.NewTwoFARepository(db)

	// Initialize authentication service
	authSrv := service.NewAuthService(userRepo, twoFARepo, otpRepo, tokenRepo, jwtManager, emailClient, googleOAuthConfig)

	// Initialize HTTP handlers
	h := handler.NewHandler(*authSrv)

	// Setup Gin router with middleware and routes
	r := router.SetupRouter(h, redisClient, jwtManager)

	// Create HTTP server instance
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		logger.Info("HTTP server starting", "port", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server failed", "error", err)
		}
	}()

	// Wait for interrupt signal (SIGINT) to trigger graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	logger.Info("Shutdown signal received...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform graceful shutdown
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", "error", err)
	} else {
		logger.Info("Server stopped gracefully")
	}
}