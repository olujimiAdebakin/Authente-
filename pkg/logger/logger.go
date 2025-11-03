package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sync"
)

// Global variables for the logger instances and synchronization control.
var (
	// Logger is the high-performance, structured core zap.Logger instance.
	// It should be used when logging performance is the absolute priority (zero allocation).
	Logger *zap.Logger
	
	// Sugar is the flexible, user-friendly zap.SugaredLogger instance.
	// It is used for easier logging with printf-style formatting or loose key-value pairs.
	Sugar *zap.SugaredLogger
	
	// once ensures the logger initialization logic runs only one time across all goroutines.
	once sync.Once
)

// InitLogger initializes the global Logger and Sugar instances.
// It must be called once at application startup (e.g., in main.go).
// Pass isProduction=true to get JSON output, which is standard for cloud environments/log parsers.
// Pass isProduction=false to get colorful, console-friendly output for development.
func InitLogger(isProduction bool) error {
	// Declare a local error variable to capture the result of the initialization.
	// This avoids using a package-level (global) error variable, improving thread safety and clarity.
	var err error
	
	// once.Do guarantees that the anonymous function inside will be executed exactly once.
	once.Do(func() {
		// Initialization logic
		var l *zap.Logger // Temporary variable to hold the initialized logger
		
		if isProduction {
			// zap.NewProduction() creates a logger configured for high performance,
			// logging at the Info level and outputting messages in JSON format.
			l, err = zap.NewProduction()
		} else {
			// zap.NewDevelopmentConfig() creates a logger configured for developer use,
			// logging at the Debug level and outputting messages to the console with colors.
			cfg := zap.NewDevelopmentConfig()
			
			// Customizes the development configuration to ensure log levels (DEBUG, INFO, etc.)
			// are displayed with capitalization and console colors.
			cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			l, err = cfg.Build()
		}
		
		// If an error occurred during logger building, capture it and stop initialization.
		if err != nil {
			return
		}
		
		// Assign the built core logger to the global Logger variable.
		Logger = l
		
		// Create the sugared wrapper and assign it to the global Sugar variable.
		Sugar = Logger.Sugar()
	})
	
	// Return the local err variable, which holds any error captured inside once.Do.
	return err
}

// Debug logs a debug message using the sugared logger.
// Debug messages should be detailed and used primarily during development/troubleshooting.
// It accepts alternating key-value pairs (e.g., "user_id", 42).
func Debug(msg string, keysAndValues ...interface{}) {
	if Sugar != nil {
		Sugar.Debugw(msg, keysAndValues...)
	}
}

// Info logs an info message using the sugared logger.
// Info messages represent normal, expected application events (e.g., server started, request processed).
func Info(msg string, keysAndValues ...interface{}) {
	if Sugar != nil {
		Sugar.Infow(msg, keysAndValues...)
	}
}

// Warn logs a warning message using the sugared logger.
// Warnings indicate unusual events that might be non-critical but should be noted (e.g., deprecated API use).
func Warn(msg string, keysAndValues ...interface{}) {
	if Sugar != nil {
		Sugar.Warnw(msg, keysAndValues...)
	}
}

// Error logs an error message using the sugared logger.
// Errors indicate unexpected failures that should be investigated (e.g., database connection failure).
func Error(msg string, keysAndValues ...interface{}) {
	if Sugar != nil {
		Sugar.Errorw(msg, keysAndValues...)
	}
}

// Fatal logs a fatal message then calls os.Exit(1), using the sugared logger.
// Fatal errors mean the application cannot recover and must shut down immediately.
func Fatal(msg string, keysAndValues ...interface{}) {
	if Sugar != nil {
		Sugar.Fatalw(msg, keysAndValues...)
	}
}

// Sync flushes any buffered log entries to the output destination (like stdout or a file).
// This is critical to call when the application is shutting down gracefully to ensure
// no pending log messages are lost.
func Sync() error {
	var err error
	
	// Always check and attempt to sync the sugared logger first.
	if Sugar != nil {
		err = Sugar.Sync()
	}
	
	// Then, explicitly sync the core logger if it exists.
	if Logger != nil {
		err2 := Logger.Sync()
		
		// If the sugared logger sync was successful (err == nil), use the core logger's error.
		// This prioritizes the error from the sugared logger if both fail, but ensures we return
		// an error if either sync fails.
		if err == nil {
			err = err2
		}
	}
	
	return err
}
