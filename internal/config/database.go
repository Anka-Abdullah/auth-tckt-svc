// FILE: ./internal/config/database.go
package config

import (
	"fmt"
	"time"

	"auth-svc-ticketing/internal/core/domain"
	customLogger "auth-svc-ticketing/pkg/logger"

	"github.com/go-redis/redis/v8"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// InitializeDatabase - Initialize PostgreSQL connection
func InitializeDatabase(cfg *Config, appLogger *customLogger.Logger) (*gorm.DB, error) {
	// Nonaktifkan logger GORM untuk menghindari slow query warnings
	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
		PrepareStmt:                              true,
		Logger:                                   nil,
		DisableForeignKeyConstraintWhenMigrating: true,
		SkipDefaultTransaction:                   true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get generic database object to set connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Cek tabel users
	var count int64
	if err := db.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'").Scan(&count).Error; err != nil {
		appLogger.Warn("Failed to check table existence", "error", err)
	}

	if count == 0 {
		appLogger.Info("Creating database tables...")

		// Migrate tabel
		if err := db.AutoMigrate(
			&domain.User{},
			&domain.UserRoleModel{},
			&domain.RefreshToken{},
			&domain.PasswordResetToken{},
		); err != nil {
			return nil, fmt.Errorf("failed to auto-migrate database: %w", err)
		}

		appLogger.Info("Database tables created successfully")
	} else {
		appLogger.Info("Database tables already exist, skipping migration")
	}

	appLogger.Info("Database connection established successfully")
	return db, nil
}

// InitializeRedis - Initialize Redis connection
func InitializeRedis(cfg *Config, logger *customLogger.Logger) (*redis.Client, error) {
	// Gunakan RedisURL langsung dari config
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Redis URL: %w", err)
	}

	// Untuk Redis dengan SSL/TLS (rediss://)
	// ParseURL sudah menangani ini otomatis

	client := redis.NewClient(opt)

	// Test connection
	ctx := client.Context()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info("Redis connection established successfully",
		"address", opt.Addr)
	return client, nil
}
