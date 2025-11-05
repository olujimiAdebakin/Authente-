package middleware

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type RedisRateLimiter struct {
	redis      *redis.Client
	limit      int           // Number of requests
	window     time.Duration // Time window
	keyPrefix  string
}

func NewRedisRateLimiter(redis *redis.Client, limit int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		redis:     redis,
		limit:     limit,
		window:    window,
		keyPrefix: "ratelimit:",
	}
}

// RateLimiterMiddlewareRedis returns a Gin middleware for rate limiting using Redis
func RateLimiterMiddlewareRedis(redis *redis.Client) gin.HandlerFunc {
	limiter := NewRedisRateLimiter(redis, 10, time.Minute) // 100 requests per minute
	return limiter.Handle
}

func (rl *RedisRateLimiter) Handle(c *gin.Context) {
	key := rl.getKey(c)
	ctx := context.Background()

	// Use Redis MULTI to ensure atomic operations
	pipe := rl.redis.Pipeline()
	
	// Get current count
	// countCmd := pipe.Get(ctx, key)
	// Increment
	incrCmd := pipe.Incr(ctx, key)
	// Set expiry if not exists
	pipe.Expire(ctx, key, rl.window)
	
	_, err := pipe.Exec(ctx)

	// Key doesn't exist yet
	if err == redis.Nil {
		pipe := rl.redis.Pipeline()
		pipe.Set(ctx, key, 1, rl.window)
		if _, err := pipe.Exec(ctx); err != nil {
			logger.Logger.Error("redis rate limiter error", zap.Error(err))
			c.Next() // Allow request on redis error
			return
		}
		c.Next()
		return
	}

	// Other redis errors
	if err != nil && err != redis.Nil {
		logger.Logger.Error("redis rate limiter error", zap.Error(err))
		c.Next() // Allow request on redis error
		return
	}

	count, err := incrCmd.Result()
	if err != nil {
		logger.Logger.Error("redis rate limiter error", zap.Error(err))
		c.Next()
		return
	}

	// Add rate limit headers
	c.Header("X-RateLimit-Limit", strconv.Itoa(rl.limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(rl.limit-int(count)))
	
	// Check if over limit
	if count > int64(rl.limit) {
		logger.Logger.Warn("rate limit exceeded",
			zap.String("ip", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
		)
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "rate limit exceeded",
			"retry_after": rl.window.Seconds(),
		})
		c.Abort()
		return
	}

	c.Next()
}

// getKey generates a rate limit key based on IP and path
func (rl *RedisRateLimiter) getKey(c *gin.Context) string {
	return rl.keyPrefix + c.ClientIP() + ":" + c.Request.URL.Path
}