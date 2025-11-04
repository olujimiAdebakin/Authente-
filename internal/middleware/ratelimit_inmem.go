package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type visitor struct {
	count    int
	lastSeen time.Time
}

type InMemoryRateLimiter struct {
	sync.RWMutex
	visitors map[string]*visitor
	limit    int           // Number of requests
	window   time.Duration // Time window
}

func NewInMemoryRateLimiter(limit int, window time.Duration) *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}

	// Start cleanup routine
	go limiter.cleanup()

	return limiter
}

// RateLimiterMiddlewareInMem returns a Gin middleware for rate limiting using in-memory storage
func RateLimiterMiddlewareInMem() gin.HandlerFunc {
	limiter := NewInMemoryRateLimiter(100, time.Minute) // 100 requests per minute
	return limiter.Handle
}

func (rl *InMemoryRateLimiter) Handle(c *gin.Context) {
	key := c.ClientIP() + ":" + c.Request.URL.Path
	now := time.Now()

	rl.Lock()
	v, exists := rl.visitors[key]
	if !exists {
		rl.visitors[key] = &visitor{count: 1, lastSeen: now}
		rl.Unlock()
		c.Next()
		return
	}

	// Reset count if window has passed
	if now.Sub(v.lastSeen) > rl.window {
		v.count = 1
		v.lastSeen = now
	} else {
		v.count++
	}

	// Add rate limit headers
	c.Header("X-RateLimit-Limit", strconv.Itoa(rl.limit))
	c.Header("X-RateLimit-Remaining", strconv.Itoa(rl.limit-v.count))

	if v.count > rl.limit {
		rl.Unlock()
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

	rl.Unlock()
	c.Next()
}

// cleanup removes old entries periodically
func (rl *InMemoryRateLimiter) cleanup() {
	for {
		time.Sleep(rl.window)
		now := time.Now()

		rl.Lock()
		for ip, v := range rl.visitors {
			if now.Sub(v.lastSeen) > rl.window {
				delete(rl.visitors, ip)
			}
		}
		rl.Unlock()
	}
}