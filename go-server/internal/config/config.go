package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config represents the application configuration
type Config struct {
	Server struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
		TLS  struct {
			Enabled  bool   `mapstructure:"enabled"`
			CertFile string `mapstructure:"cert_file"`
			KeyFile  string `mapstructure:"key_file"`
		} `mapstructure:"tls"`
	} `mapstructure:"server"`

	Storage struct {
		Type string `mapstructure:"type"` // "filesystem", "s3", etc.
		Path string `mapstructure:"path"` // Base path for filesystem storage
		// S3 config fields would go here if needed
	} `mapstructure:"storage"`

	Security struct {
		JWTSecret            string `mapstructure:"jwt_secret"`
		JWTExpirationMinutes int    `mapstructure:"jwt_expiration_minutes"`
		EnableRateLimit      bool   `mapstructure:"enable_rate_limit"`
		MaxUploadSizeMB      int    `mapstructure:"max_upload_size_mb"`
	} `mapstructure:"security"`

	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
}

// Load loads configuration from file
func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}

// SetupLogger creates a new logger based on configuration
func SetupLogger(level, format string) (*zap.Logger, error) {
	var logLevel zapcore.Level
	if err := logLevel.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	var config zap.Config
	if format == "json" {
		config = zap.NewProductionConfig()
	} else {
		config = zap.NewDevelopmentConfig()
	}
	config.Level = zap.NewAtomicLevelAt(logLevel)

	return config.Build()
}
