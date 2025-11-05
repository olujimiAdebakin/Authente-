package middleware

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"authentio/pkg/jwt"
	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// =============================================================================
// GeoIP Data Structures
// =============================================================================

// IPAPIResponse structure for ip-api.com JSON response
// Contains geographical and ISP information for IP address lookup
type IPAPIResponse struct {
	Status      string  `json:"status"`       // Request status: "success" or "fail"
	Country     string  `json:"country"`      // Country name
	CountryCode string  `json:"countryCode"`  // ISO 3166-1 alpha-2 country code
	Region      string  `json:"region"`       // Region/state code
	RegionName  string  `json:"regionName"`   // Region/state name
	City        string  `json:"city"`         // City name
	Lat         float64 `json:"lat"`          // Latitude
	Lon         float64 `json:"lon"`          // Longitude
	Timezone    string  `json:"timezone"`     // Timezone (e.g., "America/New_York")
	ISP         string  `json:"isp"`          // Internet Service Provider name
	Org         string  `json:"org"`          // Organization name
	AS          string  `json:"as"`           // Autonomous system name
	Query       string  `json:"query"`        // Original IP address queried
}

// =============================================================================
// Configuration and Environment Variables
// =============================================================================

// GeoIP configuration loaded from environment variables
var (
	// IPAPI_URL: External GeoIP service endpoint (default: ip-api.com)
	ipapiURL = getEnv("IPAPI_URL", "http://ip-api.com/json/")
	
	// BLOCKED_COUNTRIES: Comma-separated list of country codes to block entirely
	blockedCountries = loadCountries("BLOCKED_COUNTRIES")
	
	// SUSPICIOUS_COUNTRIES: Comma-separated list of country codes to monitor
	suspiciousCountries = loadCountries("SUSPICIOUS_COUNTRIES")
	
	// ALLOWED_COUNTRIES: Comma-separated list of country codes to allow (optional)
	allowedCountries = loadCountries("ALLOWED_COUNTRIES")
)

// getEnv retrieves environment variable with fallback to default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// loadCountries parses comma-separated country codes from environment variable
// into a map for efficient lookup
func loadCountries(envVar string) map[string]bool {
	countries := make(map[string]bool)
	envValue := os.Getenv(envVar)
	if envValue == "" {
		return countries
	}
	
	for _, country := range strings.Split(envValue, ",") {
		country = strings.TrimSpace(country)
		if country != "" {
			countries[country] = true
		}
	}
	return countries
}

// =============================================================================
// Authentication Middleware
// =============================================================================

// AuthRequired creates a Gin middleware that validates JWT tokens and enforces
// geographical access restrictions. This is the main authentication guard for protected routes.
//
// Features:
// - JWT token validation
// - GeoIP-based access control
// - Request context enrichment with user and location data
// - Security monitoring for suspicious locations
//
// Parameters:
//   - jwtManager: JWT manager instance for token verification
//
// Returns:
//   - gin.HandlerFunc: Authentication middleware function
func AuthRequired(jwtManager *jwt.Manager) gin.HandlerFunc {
	httpClient := &http.Client{Timeout: 3 * time.Second} // GeoIP API client with timeout
	
	return func(c *gin.Context) {
		// Extract and validate Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Debug("missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			c.Abort()
			return
		}

		// Parse Bearer token format: "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			logger.Debug("invalid authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			c.Abort()
			return
		}

		token := parts[1]
		
		// Verify JWT token signature and expiration
		claims, err := jwtManager.VerifyToken(token)
		if err != nil {
			logger.Debug("invalid token", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Extract user information from token claims
		userID, ok := claims["user_id"].(float64)
		if !ok {
			logger.Debug("missing user_id in token")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token claims"})
			c.Abort()
			return
		}

		email, _ := claims["email"].(string)
		firstName, _ := claims["first_name"].(string)
		lastName, _ := claims["last_name"].(string)
		fullName, _ := claims["name"].(string)

		// Perform GeoIP lookup for geographical restrictions
		countryCode, countryName := getGeoIPInfo(c, httpClient)
		
		// Check if country is blocked
		if isCountryBlocked(countryCode) {
			logger.Warn("blocked access from restricted country",
				zap.Int64("userID", int64(userID)),
				zap.String("email", email),
				zap.String("ip", c.ClientIP()),
				zap.String("country", countryCode),
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "access denied from your region"})
			c.Abort()
			return
		}
		
		// Enrich request context with user and location information
		// This data is available to subsequent handlers in the chain
		c.Set("userID", int64(userID))
		c.Set("email", email)
		c.Set("firstName", firstName)
		c.Set("lastName", lastName)
		c.Set("fullName", fullName)
		c.Set("country", countryCode)
		c.Set("countryName", countryName)
		c.Set("clientIP", c.ClientIP())

		logger.Debug("authenticated request",
			zap.Int64("userID", int64(userID)),
			zap.String("email", email),
			zap.String("ip", c.ClientIP()),
			zap.String("country", countryCode),
		)

		// Log warning for suspicious countries (monitoring purposes)
		if isSuspiciousCountry(countryCode) {
			logger.Warn("login from suspicious country",
				zap.Int64("userID", int64(userID)),
				zap.String("email", email),
				zap.String("ip", c.ClientIP()),
				zap.String("country", countryCode),
			)
		}

		// Proceed to next middleware/handler
		c.Next()
	}
}

// =============================================================================
// GeoIP Utility Functions
// =============================================================================

// isCountryBlocked checks if a country code is in the blocked countries list
func isCountryBlocked(countryCode string) bool {
	return blockedCountries[countryCode]
}

// isSuspiciousCountry checks if a country code is in the suspicious countries list
func isSuspiciousCountry(countryCode string) bool {
	return suspiciousCountries[countryCode]
}

// getGeoIPInfo performs IP geolocation lookup using external GeoIP service
//
// Parameters:
//   - c: Gin context for client IP and logging
//   - client: HTTP client for making GeoIP API requests
//
// Returns:
//   - string: Country code (e.g., "US", "GB", "LOCAL", "UNKNOWN")
//   - string: Country name or description
func getGeoIPInfo(c *gin.Context, client *http.Client) (string, string) {
	clientIP := c.ClientIP()
	
	// Handle local development addresses
	if clientIP == "::1" || clientIP == "127.0.0.1" || clientIP == "localhost" {
		return "LOCAL", "Localhost"
	}

	// Handle empty IP addresses
	if clientIP == "" {
		return "UNKNOWN", "Unknown"
	}

	// Construct GeoIP API URL
	url := ipapiURL + clientIP
	
	// Make HTTP request to GeoIP service
	resp, err := client.Get(url)
	if err != nil {
		logger.Debug("ipapi request failed", 
			zap.String("ip", clientIP), 
			zap.Error(err),
		)
		return "UNKNOWN", "Unknown"
	}
	defer resp.Body.Close()

	// Parse JSON response from GeoIP service
	var result IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Debug("ipapi decode failed", 
			zap.String("ip", clientIP), 
			zap.Error(err),
		)
		return "UNKNOWN", "Unknown"
	}

	// Return country information if request was successful
	if result.Status == "success" {
		return result.CountryCode, result.Country
	}

	return "UNKNOWN", "Unknown"
}

// =============================================================================
// Standalone GeoIP Middleware
// =============================================================================

// GeoIPMiddleware creates a Gin middleware that performs GeoIP lookup
// and adds location information to the request context.
// This can be used independently of authentication for public routes.
//
// Returns:
//   - gin.HandlerFunc: GeoIP middleware function
func GeoIPMiddleware() gin.HandlerFunc {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	
	return func(c *gin.Context) {
		countryCode, countryName := getGeoIPInfo(c, httpClient)
		
		// Add location information to context for subsequent handlers
		c.Set("country", countryCode)
		c.Set("countryName", countryName)
		c.Set("clientIP", c.ClientIP())
		
		c.Next()
	}
}