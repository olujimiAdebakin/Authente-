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
		"authentio/pkg/jwt"
		"authentio/pkg/logger"

		"github.com/gin-gonic/gin"
		"github.com/redis/go-redis/v9"
		_ "github.com/jackc/pgx/v5/stdlib"
	)

	func main() {
		// Load config from env or .env
		cfg, err := config.LoadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
			os.Exit(1)
		}

		// Initialize Logger
		if err := logger.InitLogger(cfg.Env == "production"); err != nil {
			fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
			os.Exit(1)
		}
		defer logger.Sync()

		logger.Info("Starting Authentio service", "env", cfg.Env, "port", cfg.ServerPort)

		// Set Gin mode
		if cfg.Env == "production" {
			gin.SetMode(gin.ReleaseMode)
		} else {
			gin.SetMode(gin.DebugMode)
		}

		// Initialize Postgres connection
		db, err := sql.Open("pgx", cfg.PostgresDSN)
		if err != nil {
			logger.Fatal("failed to open database", "error", err)
		}
		defer db.Close()

		// Ping DB to ensure connectivity
		ctxPing, cancelPing := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelPing()
		if err := db.PingContext(ctxPing); err != nil {
			logger.Fatal("failed to ping database", "error", err)
		}

		// Initialize Redis
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.RedisAddr,
			Password: cfg.RedisPass,
		})
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			logger.Fatal("failed to connect to redis", "error", err)
		}

		// JWT manager
		jwtManager := jwt.NewManager(cfg.JWTSecret)

		// Repositories
		userRepo := dbpkg.NewUserRepository(db)
		tokenRepo := dbpkg.NewTokenRepository(db)
		otpRepo := dbpkg.NewOTPRepository(db)
		twoFARepo := dbpkg.NewTwoFARepository(db)

		// Services
		authSrvPtr := service.NewAuthService(userRepo, twoFARepo, otpRepo, tokenRepo, jwtManager)
		// handler package expects a value type for AuthService, so pass a dereferenced value
		authSrv := *authSrvPtr

		// Handlers
		h := handler.NewHandler(authSrv)

		// Router
		r := router.SetupRouter(h, redisClient, jwtManager)

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
