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

// IPAPIResponse structure for ip-api.com
type IPAPIResponse struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Query       string  `json:"query"`
}

// Load configuration from environment
var (
	ipapiURL          = getEnv("IPAPI_URL", "http://ip-api.com/json/")
	blockedCountries   = loadCountries("BLOCKED_COUNTRIES")
	suspiciousCountries = loadCountries("SUSPICIOUS_COUNTRIES")
	allowedCountries   = loadCountries("ALLOWED_COUNTRIES")
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

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

// AuthRequired middleware
func AuthRequired(jwtManager *jwt.Manager) gin.HandlerFunc {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Debug("missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			c.Abort()
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			logger.Debug("invalid authorization header format")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization format"})
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := jwtManager.VerifyToken(token)
		if err != nil {
			logger.Debug("invalid token", zap.Error(err))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

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

		countryCode, countryName := getGeoIPInfo(c, httpClient)
		
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

		if isSuspiciousCountry(countryCode) {
			logger.Warn("login from suspicious country",
				zap.Int64("userID", int64(userID)),
				zap.String("email", email),
				zap.String("ip", c.ClientIP()),
				zap.String("country", countryCode),
			)
		}

		c.Next()
	}
}

func isCountryBlocked(countryCode string) bool {
	return blockedCountries[countryCode]
}

func isSuspiciousCountry(countryCode string) bool {
	return suspiciousCountries[countryCode]
}

func getGeoIPInfo(c *gin.Context, client *http.Client) (string, string) {
	clientIP := c.ClientIP()
	
	if clientIP == "::1" || clientIP == "127.0.0.1" || clientIP == "localhost" {
		return "LOCAL", "Localhost"
	}

	if clientIP == "" {
		return "UNKNOWN", "Unknown"
	}

	// Use the URL from environment
	url := ipapiURL + clientIP
	
	resp, err := client.Get(url)
	if err != nil {
		logger.Debug("ipapi request failed", zap.String("ip", clientIP), zap.Error(err))
		return "UNKNOWN", "Unknown"
	}
	defer resp.Body.Close()

	var result IPAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		logger.Debug("ipapi decode failed", zap.String("ip", clientIP), zap.Error(err))
		return "UNKNOWN", "Unknown"
	}

	if result.Status == "success" {
		return result.CountryCode, result.Country
	}

	return "UNKNOWN", "Unknown"
}

func GeoIPMiddleware() gin.HandlerFunc {
	httpClient := &http.Client{Timeout: 3 * time.Second}
	
	return func(c *gin.Context) {
		countryCode, countryName := getGeoIPInfo(c, httpClient)
		c.Set("country", countryCode)
		c.Set("countryName", countryName)
		c.Set("clientIP", c.ClientIP())
		c.Next()
	}
}