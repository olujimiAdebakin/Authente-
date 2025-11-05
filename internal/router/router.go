package router

import (
	"net/http"
	"os"

	"authentio/internal/handler"
	"authentio/internal/middleware"
	"authentio/pkg/jwt"
	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	// Swagger imports
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupRouter godoc
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

// SetupRouter configures and returns a Gin engine with all routes, middleware,
// security policies, and health checks configured for the Authentio API.
//
// Parameters:
//   - h: Handler instance containing all route handlers
//   - redis: Redis client for rate limiting and token blacklisting
//   - jwtManager: JWT manager for token validation and generation
//
// Returns:
//   - *gin.Engine: Fully configured Gin router ready to serve HTTP requests
func SetupRouter(h *handler.Handler, redis *redis.Client, jwtManager *jwt.Manager) *gin.Engine {
	// Initialize the Gin engine with default middleware
	r := gin.New()

	// =========================================================================
	// Global Middleware Stack
	// =========================================================================

	// Recovery middleware recovers from any panics and returns a 500 error
	r.Use(gin.Recovery())

	// Custom structured request logger for consistent request logging
	r.Use(middleware.RequestLogger())

	// CORS middleware handles Cross-Origin Resource Sharing headers
	r.Use(middleware.CORSMiddleware())

	// GeoIP middleware extracts geographical information from client IP addresses
	// Used for security monitoring and regional access control
	r.Use(middleware.GeoIPMiddleware())

	// Environment-specific rate limiting
	// In production: Use Redis-based distributed rate limiting for scalability
	// In development: Use in-memory rate limiting for simplicity
	if os.Getenv("APP_ENV") == "production" {
		r.Use(middleware.RateLimiterMiddlewareRedis(redis))
	} else {
		r.Use(middleware.RateLimiterMiddlewareInMem())
	}

	// Token blacklist middleware checks if JWT tokens have been invalidated
	// Prevents use of logged-out or revoked tokens
	r.Use(middleware.BlacklistMiddleware(redis))

	// =========================================================================
	// Public Routes - No Authentication Required
	// =========================================================================

	// Health check endpoint for load balancers and monitoring systems
	// Returns simple status to indicate service availability
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Swagger documentation endpoint
	// Serves auto-generated API documentation at /swagger/index.html
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// =========================================================================
	// API v1 Routes - Main Application Endpoints
	// =========================================================================
	api := r.Group("/api/v1")
	{
		// =====================================================================
		// Authentication Routes - Public access
		// =====================================================================
		auth := api.Group("/auth")
		{
			// Google OAuth2 authentication endpoints
			// Frontend sends ID token directly (mobile/app flow)
			auth.POST("/google/login", h.GoogleLogin)

			// Server-side OAuth redirect flow (web flow)
			// Initiates OAuth dance with Google
			auth.GET("/google/redirect", h.GoogleRedirect)

			// OAuth callback endpoint - Google redirects here with authorization code
			auth.GET("/google/callback", h.GoogleCallback)

			// Basic email/password authentication
			// User registration with email verification
			auth.POST("/register", h.Register)

			// User login with credentials, returns JWT tokens
			auth.POST("/login", h.Login)

			// Refresh access token using valid refresh token
			auth.POST("/refresh", h.Refresh)

			// Password reset flow
			// Step 1: Request password reset (sends email with reset code)
			auth.POST("/forgot-password", h.ForgotPassword)

			// Step 2: Verify reset code and set new password
			auth.POST("/reset-password", h.ResetPassword)

			// Public 2FA verification endpoint
			// Used during login flow after credentials are verified
			auth.POST("/2fa/verify", h.Verify2FA)
		}

		// =====================================================================
		// Two-Factor Authentication Management - Protected routes
		// Requires valid JWT token
		// =====================================================================
		twoFA := api.Group("/2fa")
		twoFA.Use(middleware.AuthRequired(jwtManager)) // JWT authentication required
		{
			// Enable email-based 2FA for the authenticated user
			twoFA.POST("/enableOtp", h.EnableEmail2FA)

			// Disable 2FA for the authenticated user
			twoFA.POST("/disableOtp", h.Disable2FA)

			// Send a new 2FA OTP code to the user's email
			// Used when user needs a new code or previous code expired
			twoFA.POST("/sendOtp", h.SendOTP)
		}

		// =====================================================================
		// User Profile Management - Protected routes
		// Requires valid JWT token
		// =====================================================================
		user := api.Group("/user")
		user.Use(middleware.AuthRequired(jwtManager)) // JWT authentication required
		{
			// Retrieve the authenticated user's profile information
			// Returns user details without sensitive data like password
			user.GET("/getProfile", h.GetProfile)

			// Update the authenticated user's profile information
			// Supports partial updates of firstName, lastName, and email
			user.PUT("/updateProfile", h.UpdateProfile)
		}
	}

	// =========================================================================
	// 404 Handler - Catch all undefined routes
	// =========================================================================
	r.NoRoute(func(c *gin.Context) {
		logger.Warn("Route not found",
			zap.String("path", c.Request.URL.Path),
			zap.String("method", c.Request.Method),
			zap.String("ip", c.ClientIP()),
		)
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "endpoint not found",
			"path":    c.Request.URL.Path,
			"message": "The requested API endpoint does not exist",
		})
	})

	// =========================================================================
	// Router Configuration Complete
	// =========================================================================
	logger.Info("Router configuration completed",
		zap.Bool("production", os.Getenv("APP_ENV") == "production"),
		zap.Bool("redis_rate_limiting", os.Getenv("APP_ENV") == "production"),
		zap.Bool("swagger_enabled", true),
	)

	return r
}