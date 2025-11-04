package middleware

import (
	"net/http"
	"strings"

	"authentio/pkg/jwt"
	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// AuthRequired middleware checks for a valid JWT token in the Authorization header
func AuthRequired(jwtManager *jwt.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			logger.Debug("missing authorization header")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization required"})
			c.Abort()
			return
		}

		// Check Bearer prefix
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

		// Extract values from MapClaims (it's a map, not a struct)
		userID, ok := claims["user_id"].(float64) // JWT numbers are float64
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

		// Store user information in context (convert float64 to int64)
		c.Set("userID", int64(userID))
		c.Set("email", email)
		c.Set("firstName", firstName)
		c.Set("lastName", lastName)
		c.Set("fullName", fullName)

		logger.Debug("authenticated request",
			zap.Int64("userID", int64(userID)),
			zap.String("email", email),
		)

		c.Next()
	}
}