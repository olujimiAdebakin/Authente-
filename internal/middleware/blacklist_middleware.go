package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type TokenBlacklist struct {
	redis     *redis.Client
	keyPrefix string
}

func NewTokenBlacklist(redis *redis.Client) *TokenBlacklist {
	return &TokenBlacklist{
		redis:     redis,
		keyPrefix: "blacklist:",
	}
}

// BlacklistMiddleware checks if a token is blacklisted
func BlacklistMiddleware(redis *redis.Client) gin.HandlerFunc {
	blacklist := NewTokenBlacklist(redis)
	return blacklist.Handle
}

func (bl *TokenBlacklist) Handle(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.Next()
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.Next()
		return
	}

	token := parts[1]
	isBlacklisted, err := bl.IsBlacklisted(c.Request.Context(), token)
	if err != nil {
		logger.Logger.Error("blacklist check failed", zap.Error(err))
		c.Next() // Allow on redis error
		return
	}

	if isBlacklisted {
		logger.Logger.Warn("blacklisted token used",
			zap.String("ip", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked"})
		c.Abort()
		return
	}

	c.Next()
}

// Blacklist adds a token to the blacklist with an expiration
func (bl *TokenBlacklist) Blacklist(ctx context.Context, token string, expiration time.Duration) error {
	key := bl.keyPrefix + token
	return bl.redis.Set(ctx, key, "1", expiration).Err()
}

// IsBlacklisted checks if a token is in the blacklist
func (bl *TokenBlacklist) IsBlacklisted(ctx context.Context, token string) (bool, error) {
	key := bl.keyPrefix + token
	exists, err := bl.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// RemoveFromBlacklist removes a token from the blacklist
func (bl *TokenBlacklist) RemoveFromBlacklist(ctx context.Context, token string) error {
	key := bl.keyPrefix + token
	return bl.redis.Del(ctx, key).Err()
}