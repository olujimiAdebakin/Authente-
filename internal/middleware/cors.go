package middleware

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// CORS Middleware
// =============================================================================

// CORSMiddleware creates a Gin middleware that handles Cross-Origin Resource Sharing (CORS).
// This middleware enables secure cross-origin requests for web applications.
//
// CORS is a security feature that allows restricted resources on a web page to be requested
// from another domain outside the domain from which the first resource was served.
//
// Features:
// - Configurable allowed origins (environment variable support)
// - Preflight request handling
// - Secure headers for credentialed requests
// - Flexible HTTP methods and headers
//
// Returns:
//   - gin.HandlerFunc: CORS middleware function
func CORSMiddleware() gin.HandlerFunc {
	// Get allowed origins from environment variable or default to all
	allowedOrigins := getCORSAllowedOrigins()

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		
		// Set Access-Control-Allow-Origin header
		// In production, you should specify exact domains instead of "*" for security
		if isOriginAllowed(origin, allowedOrigins) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			// Fallback to wildcard if no specific origins configured
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		}

		// Allow credentials (cookies, authorization headers) in cross-origin requests
		// Important: Cannot use wildcard "*" origin when credentials are allowed
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		
		// Define which headers are allowed in actual requests
		c.Writer.Header().Set("Access-Control-Allow-Headers", strings.Join([]string{
			"Content-Type",
			"Content-Length",
			"Accept-Encoding",
			"X-CSRF-Token",
			"Authorization",
			"accept",
			"origin",
			"Cache-Control",
			"X-Requested-With",
			"X-API-Key",           // Custom API key header
			"X-Client-Version",    // Client version header
			"X-Request-ID",        // Request tracing
		}, ", "))

		// Define which HTTP methods are allowed for cross-origin requests
		c.Writer.Header().Set("Access-Control-Allow-Methods", strings.Join([]string{
			"POST",
			"OPTIONS",
			"GET",
			"PUT",
			"DELETE",
			"PATCH",              // Added for partial updates
			"HEAD",               // Added for header-only requests
		}, ", "))

		// Define which response headers can be exposed to the client
		c.Writer.Header().Set("Access-Control-Expose-Headers", strings.Join([]string{
			"Content-Length",
			"Content-Type",
			"X-Request-ID",
			"X-RateLimit-Limit",
			"X-RateLimit-Remaining",
			"X-RateLimit-Reset",
		}, ", "))

		// Handle preflight requests (OPTIONS)
		// Preflight requests are sent by browsers before actual requests to check CORS permissions
		if c.Request.Method == "OPTIONS" {
			// Set cache duration for preflight responses (in seconds)
			// Browsers will cache the preflight response for this duration
			c.Writer.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
			
			// Return 204 No Content for successful preflight requests
			c.AbortWithStatus(204)
			return
		}

		// Continue to next middleware/handler for actual requests
		c.Next()
	}
}

// =============================================================================
// CORS Configuration Helpers
// =============================================================================

// getCORSAllowedOrigins retrieves and parses allowed origins from environment variable
// Format: "https://app.example.com,https://admin.example.com,http://localhost:3000"
//
// Returns:
//   - []string: List of allowed origins, empty slice means all origins allowed
func getCORSAllowedOrigins() []string {
	originsEnv := os.Getenv("CORS_ALLOWED_ORIGINS")
	if originsEnv == "" {
		return []string{} // Empty means allow all origins
	}

	origins := strings.Split(originsEnv, ",")
	allowedOrigins := make([]string, 0, len(origins))
	
	for _, origin := range origins {
		trimmedOrigin := strings.TrimSpace(origin)
		if trimmedOrigin != "" {
			allowedOrigins = append(allowedOrigins, trimmedOrigin)
		}
	}

	return allowedOrigins
}

// isOriginAllowed checks if a request origin is in the list of allowed origins
//
// Parameters:
//   - origin: The Origin header value from the request
//   - allowedOrigins: List of allowed origins from configuration
//
// Returns:
//   - bool: True if origin is allowed, false otherwise
func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return true // Allow all origins if none specified
	}

	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			return true
		}
	}

	return false
}