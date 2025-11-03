package config


import (
	"time"
	"github.com/caarlos0/env/v9"
	"github.com/joho/godotenv"
	"log"
)

type Config struct {
	ServerPort int    `env:"SERVER_PORT" envDefault:"8080"`
	Env        string `env:"APP_ENV" envDefault:"development"` // dev, staging, prod

	PostgresDSN string `env:"POSTGRES_DSN,required"`
	RedisAddr   string `env:"REDIS_ADDR" envDefault:"localhost:6379"`
	RedisPass   string `env:"REDIS_PASS"`

	JWTSecret          string        `env:"JWT_SECRET,required"`
	AccessTokenTTL     time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL    time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"168h"` // 7 days

	SMTPHost     string `env:"SMTP_HOST"`
	SMTPPort     int    `env:"SMTP_PORT"`
	SMTPUser     string `env:"SMTP_USER"`
	SMTPPassword string `env:"SMTP_PASSWORD"`

	// Add more fields as needed
}

// Load loads the config from environment variables and optionally .env file
func LoadConfig() (*Config, error) {
	// Load .env file if present (optional)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, loading from system env")
	}

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	// You can add custom validation here if needed
	if cfg.ServerPort <= 0 || cfg.ServerPort > 65535 {
		return nil,  ErrInvalidPort(cfg.ServerPort)
	}

	return cfg, nil
}

// Custom error example (optional)
type ErrInvalidPort int

func (e ErrInvalidPort) Error() string {
	return "invalid server port: " + strconv.Itoa(int(e))
}
