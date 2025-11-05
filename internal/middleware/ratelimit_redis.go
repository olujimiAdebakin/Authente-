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

// =============================================================================
// RedisRateLimiter Structure
// =============================================================================

// RedisRateLimiter implements distributed rate limiting using Redis.
// This ensures consistent rate limiting across multiple application instances.
type RedisRateLimiter struct {
	redis      *redis.Client // Redis client for distributed rate limiting
	limit      int           // Maximum number of requests allowed
	window     time.Duration // Time window for rate limiting
	keyPrefix  string        // Prefix for Redis keys to avoid collisions
}

// NewRedisRateLimiter creates a new RedisRateLimiter instance with the specified configuration.
//
// Parameters:
//   - redis: Redis client instance
//   - limit: Maximum number of requests allowed in the time window
//   - window: Duration of the rate limiting window
//
// Returns:
//   - *RedisRateLimiter: Configured rate limiter instance
func NewRedisRateLimiter(redis *redis.Client, limit int, window time.Duration) *RedisRateLimiter {
	return &RedisRateLimiter{
		redis:     redis,
		limit:     limit,
		window:    window,
		keyPrefix: "ratelimit:",
	}
}

// =============================================================================
// Middleware Factory Function
// =============================================================================

// RateLimiterMiddlewareRedis returns a Gin middleware for rate limiting using Redis.
// This middleware provides distributed rate limiting that works across multiple server instances.
//
// Parameters:
//   - redis: Redis client instance for storing rate limit counters
//
// Returns:
//   - gin.HandlerFunc: Gin middleware function that enforces rate limits
func RateLimiterMiddlewareRedis(redis *redis.Client) gin.HandlerFunc {
	// Default configuration: 100 requests per minute per IP per endpoint
	limiter := NewRedisRateLimiter(redis, 100, time.Minute)
	return limiter.Handle
}

// =============================================================================
// Rate Limiting Logic
// =============================================================================

// Handle is the main rate limiting middleware function that processes each request.
// It uses Redis pipelines for atomic operations to ensure accurate counting.
//
// The rate limiting algorithm:
// 1. Generates a unique key based on client IP and request path
// 2. Increments the counter in Redis atomically
// 3. Sets expiration on the key if it's new
// 4. Checks if the request count exceeds the limit
// 5. Returns appropriate headers and responses
func (rl *RedisRateLimiter) Handle(c *gin.Context) {
	key := rl.getKey(c)
	ctx := context.Background()

	// Use Redis pipeline for atomic operations to prevent race conditions
	pipe := rl.redis.Pipeline()
	
	// Increment the counter and set expiration in a single atomic operation
	incrCmd := pipe.Incr(ctx, key)           // Increment the counter
	pipe.Expire(ctx, key, rl.window)         // Set expiration (resets if key exists)
	
	// Execute the pipeline atomically
	_, err := pipe.Exec(ctx)

	// Handle case where key doesn't exist yet (first request)
	if err == redis.Nil {
		// Create new pipeline for initial key setup
		pipe := rl.redis.Pipeline()
		pipe.Set(ctx, key, 1, rl.window) // Set initial value with expiration
		if _, err := pipe.Exec(ctx); err != nil {
			logger.Logger.Error("redis rate limiter error - failed to set initial key", 
				zap.Error(err),
				zap.String("key", key),
				zap.String("ip", c.ClientIP()),
			)
			c.Next() // Allow request on Redis error (fail-open strategy)
			return
		}
		c.Next() // Allow the request
		return
	}

	// Handle other Redis errors
	if err != nil && err != redis.Nil {
		logger.Logger.Error("redis rate limiter error - pipeline execution failed",
			zap.Error(err),
			zap.String("key", key),
			zap.String("ip", c.ClientIP()),
		)
		c.Next() // Allow request on Redis error (fail-open strategy)
		return
	}

	// Get the incremented count result
	count, err := incrCmd.Result()
	if err != nil {
		logger.Logger.Error("redis rate limiter error - failed to get increment result",
			zap.Error(err),
			zap.String("key", key),
			zap.String("ip", c.ClientIP()),
		)
		c.Next() // Allow request on error
		return
	}

	// Add rate limit headers for client information
	c.Header("X-RateLimit-Limit", strconv.Itoa(rl.limit))
	remaining := rl.limit - int(count)
	if remaining < 0 {
		remaining = 0
	}
	c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(rl.window).Unix(), 10))
	
	// Check if request count exceeds the limit
	if count > int64(rl.limit) {
		logger.Logger.Warn("rate limit exceeded",
			zap.String("ip", c.ClientIP()),
			zap.String("path", c.Request.URL.Path),
			zap.Int64("count", count),
			zap.Int("limit", rl.limit),
			zap.String("window", rl.window.String()),
		)
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": "rate limit exceeded",
			"retry_after": rl.window.Seconds(),
			"limit": rl.limit,
			"window_seconds": rl.window.Seconds(),
		})
		c.Abort() // Stop further processing
		return
	}

	// Request is within limits, proceed to next middleware/handler
	c.Next()
}

// =============================================================================
// Utility Functions
// =============================================================================

// getKey generates a unique Redis key for rate limiting based on client IP and request path.
// This ensures rate limits are applied per-IP per-endpoint basis.
//
// Format: "ratelimit:{IP}:{Path}"
// Example: "ratelimit:192.168.1.100:/api/v1/auth/login"
//
// Parameters:
//   - c: Gin context containing request information
//
// Returns:
//   - string: Unique Redis key for rate limiting
func (rl *RedisRateLimiter) getKey(c *gin.Context) string {
	return rl.keyPrefix + c.ClientIP() + ":" + c.Request.URL.Path
}