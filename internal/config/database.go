package config

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	*gorm.DB
}

var dbInstance *Database

// InitializeDatabase initializes database connection
func InitializeDatabase(cfg *Config, appLogger any) (*Database, error) {
	if dbInstance != nil {
		return dbInstance, nil
	}

	dsn := cfg.Database.GetDSN()

	// Configure GORM logger based on environment
	var gormLogger logger.Interface
	if cfg.Server.Env == "production" {
		gormLogger = logger.Default.LogMode(logger.Warn)
	} else {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	// Connect to database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get generic database object for connection pool settings
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	sqlDB.SetConnMaxIdleTime(30 * time.Minute)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Auto-migrate models (optional - better to use migrations)
	// migrateModels(db)

	dbInstance = &Database{DB: db}

	if appLogger != nil {
		if logger, ok := appLogger.(interface{ Info(string, ...interface{}) }); ok {
			logger.Info("Database connection established")
		}
	}

	return dbInstance, nil
}

// GetDatabase returns the database instance
func GetDatabase() *Database {
	return dbInstance
}

// Close closes database connection
func (db *Database) Close() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// HealthCheck checks database health
func (db *Database) HealthCheck() error {
	sqlDB, err := db.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}
