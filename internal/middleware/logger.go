package middleware

import (
	"bytes"
	"io"
	"time"

	"authentio/pkg/logger"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	maxBodyLogSize = 1024 * 10 // 10KB limit for body logging
)

// RequestLogger returns a Gin middleware for logging HTTP requests with detailed information
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery
		method := c.Request.Method

		// Log request body for POST/PUT/PATCH requests
		var requestBody string
		if method == "POST" || method == "PUT" || method == "PATCH" {
			if c.Request.Body != nil {
				bodyBytes, err := io.ReadAll(c.Request.Body)
				if err == nil {
					if len(bodyBytes) > maxBodyLogSize {
						requestBody = string(bodyBytes[:maxBodyLogSize]) + "... (truncated)"
					} else {
						requestBody = string(bodyBytes)
					}
					// Restore the body for subsequent middleware/handlers
					c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				}
			}
		}

		// Create a custom response writer to capture the response
		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		// Process request
		c.Next()

		// Calculate latency
		latency := time.Since(start)
		status := c.Writer.Status()

		// Prepare log fields
		fields := []zap.Field{
			zap.String("method", method),
			zap.String("path", path),
			zap.Int("status", status),
			zap.Duration("latency", latency),
			zap.String("ip", c.ClientIP()),
			zap.String("user-agent", c.Request.UserAgent()),
		}

		// Add query parameters if present
		if query != "" {
			fields = append(fields, zap.String("query", query))
		}

		// Add request body if present
		if requestBody != "" {
			fields = append(fields, zap.String("request_body", requestBody))
		}

		// Add response size
		fields = append(fields, zap.Int("response_size", c.Writer.Size()))

		// Add request ID if present
		if requestID := c.GetHeader("X-Request-ID"); requestID != "" {
			fields = append(fields, zap.String("request_id", requestID))
		}

		// Add errors if any
		if len(c.Errors) > 0 {
			fields = append(fields, zap.Strings("errors", c.Errors.Errors()))
			logger.Logger.Error("request completed with errors", fields...)
		} else {
			logger.Logger.Info("request completed", fields...)
		}
	}
}

// bodyLogWriter is a custom response writer that captures the response body
type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

// Write captures the response body while writing it
func (w *bodyLogWriter) Write(b []byte) (int, error) {
	// Only store the first maxBodyLogSize bytes to prevent memory issues
	if w.body.Len() < maxBodyLogSize {
		w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}