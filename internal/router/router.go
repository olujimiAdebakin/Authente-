package router

import (
	"net/http"
	"os"

	"authentio/internal/handler"
	"authentio/internal/middleware"
	"authentio/pkg/logger"
	"authentio/pkg/jwt"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

// SetupRouter configures the Gin engine with routes, middlewares, and health checks.
func SetupRouter(h *handler.Handler, redis *redis.Client, jwtManager *jwt.Manager) *gin.Engine {
	// Initialize the Gin engine
	r := gin.New()

	// --- Global Middlewares ---
	r.Use(gin.Recovery())                      // Recover from panics
	r.Use(middleware.RequestLogger())          // Custom structured request logger
	r.Use(middleware.CORSMiddleware())   // CORS handler

	r.Use(middleware.GeoIPMiddleware())

	// Choose rate limiter based on environment
	if os.Getenv("ENV") == "production" {
		r.Use(middleware.RateLimiterMiddlewareRedis(redis))
	} else {
		r.Use(middleware.RateLimiterMiddlewareInMem())
	}
	
	// Token blacklist checking
	r.Use(middleware.BlacklistMiddleware(redis))
// Rate limiter

	// --- Health check ---
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// --- API v1 routes ---
	api := r.Group("/api/v1")
	{
		// Public authentication routes
		auth := api.Group("/auth")
		{
			// Basic authentication
			auth.POST("/register", h.Auth.Register)
			auth.POST("/login", h.Auth.Login)
			auth.POST("/refresh", h.Auth.Refresh)
			
			// Password reset flow
			auth.POST("/forgot-password", h.Auth.ForgotPassword)
			auth.POST("/reset-password", h.Auth.ResetPassword)
			
			// Public 2FA verification (for login flow)
			auth.POST("/2fa/verify", h.Auth.Verify2FA)
		}

		// Protected 2FA management routes
		twoFA := api.Group("/2fa")
		twoFA.Use(middleware.AuthRequired(jwtManager))
		{
			twoFA.POST("/enableOtp", h.TwoFA.EnableEmail2FA)  // 
			twoFA.POST("/disableOtp", h.TwoFA.Disable2FA)
			twoFA.POST("/sendOtp", h.TwoFA.SendOTP)
		}

		// Protected user routes
		user := api.Group("/user")
		user.Use(middleware.AuthRequired(jwtManager))
		{
			user.GET("/getProfile", h.User.GetProfile)        // getProfile endpoint
			user.PUT("/updateProfile", h.User.UpdateProfile)     // updateProfile endpoint
		}
	}

	// --- 404 handler ---
	r.NoRoute(func(c *gin.Context) {
		logger.Warn("Route not found", zap.String("path", c.Request.URL.Path))
		c.JSON(http.StatusNotFound, gin.H{"error": "endpoint not found"})
	})

	return r
}