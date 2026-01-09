package config

import (
	"fmt"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	App      AppConfig      `yaml:"app"`
	Database DatabaseConfig `yaml:"database"`
	Redis    RedisConfig    `yaml:"redis"`
	Auth     AuthConfig     `yaml:"auth"`
}

type AppConfig struct {
	Name string `yaml:"name" env:"APP_NAME" env-default:"ModernAuth"`
	Port string `yaml:"port" env:"PORT" env-default:"8080"`
	Env  string `yaml:"env" env:"APP_ENV" env-default:"development"`
}

type DatabaseConfig struct {
	URL string `yaml:"url" env:"DATABASE_URL" env-required:"true"`
}

type RedisConfig struct {
	URL string `yaml:"url" env:"REDIS_URL" env-default:"redis://localhost:6379"`
}

type AuthConfig struct {
	JWTSecret       string        `yaml:"jwt_secret" env:"JWT_SECRET" env-required:"true"`
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl" env:"ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" env:"REFRESH_TOKEN_TTL" env-default:"168h"`
}

func Load() (*Config, error) {
	cfg := &Config{}

	// Try loading from .env file first, but don't fail if it doesn't exist
	// cleanenv.ReadConfig will read from environment variables if file not found or if env vars are set
	if err := cleanenv.ReadConfig(".env", cfg); err != nil {
		// If .env doesn't exist, try reading purely from environment variables
		if err := cleanenv.ReadEnv(cfg); err != nil {
			return nil, fmt.Errorf("config error: %w", err)
		}
	}

	return cfg, nil
}
