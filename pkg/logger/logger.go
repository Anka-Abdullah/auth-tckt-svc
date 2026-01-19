package logger

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.SugaredLogger
	zapLogger *zap.Logger
}

func NewLogger(env string) *Logger {
	var config zap.Config

	if env == "production" {
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	} else {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Add caller information
	config.EncoderConfig.CallerKey = "caller"
	config.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	// Build the logger
	zapLogger, err := config.Build(zap.AddCallerSkip(1))
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}

	return &Logger{
		SugaredLogger: zapLogger.Sugar(),
		zapLogger:     zapLogger,
	}
}

// Structured logging methods
func (l *Logger) Info(msg string, fields ...interface{}) {
	l.SugaredLogger.Infow(msg, fields...)
}

func (l *Logger) Error(msg string, err error, fields ...any) {
	allFields := append(fields, "error", err)
	l.SugaredLogger.Errorw(msg, allFields...)
}

func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.SugaredLogger.Warnw(msg, fields...)
}

func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.SugaredLogger.Debugw(msg, fields...)
}

func (l *Logger) Fatal(msg string, fields ...interface{}) {
	l.SugaredLogger.Fatalw(msg, fields...)
}

// Echo middleware for request logging
func (l *Logger) EchoLogger() echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:        true,
		LogStatus:     true,
		LogMethod:     true,
		LogLatency:    true,
		LogRemoteIP:   true,
		LogUserAgent:  true,
		LogRequestID:  true,
		LogHost:       true,
		LogError:      true,
		HandleError:   true,
		LogValuesFunc: l.logValuesFunc,
	})
}

func (l *Logger) logValuesFunc(c echo.Context, v middleware.RequestLoggerValues) error {
	fields := []interface{}{
		"method", v.Method,
		"uri", v.URI,
		"status", v.Status,
		"latency", v.Latency.String(),
		"remote_ip", v.RemoteIP,
		"user_agent", v.UserAgent,
		"request_id", v.RequestID,
		"host", v.Host,
	}

	if v.Error != nil {
		l.Error("HTTP Request Error", v.Error, fields...)
	} else {
		l.Info("HTTP Request", fields...)
	}

	return nil
}

// Sync logger - call before application exits
func (l *Logger) Sync() error {
	return l.zapLogger.Sync()
}

// Helper to get function name for logging
func GetFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	fullName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(fullName, ".")
	return parts[len(parts)-1]
}
