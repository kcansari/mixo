package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	DB     DBConfig
	App    AppConfig
	Mail   MailConfig
	Google GoogleConfig
}

type DBConfig struct {
	PG    PGConfig
	Redis RedisConfig
}

type PGConfig struct {
	Host     string
	Port     string
	User     string
	Name     string
	Password string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type AppConfig struct {
	JWTSecret       string
	Development     string
	FrontendURL     string
	CipherSecretKey string
	HMAC_SECRET_KEY string
	AWS             AwsConfig
}

type AwsConfig struct {
	Region string
	Bucket string
}

type MailConfig struct {
	Host string
	Port int
	User string
	Pass string
}

type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

func Load() (*Config, error) {
	pgHost := getEnv("POSTGRES_HOST", "localhost")
	pgPort := getEnv("POSTGRES_PORT", "5432")

	redisHost := getEnv("REDIS_HOST", "localhost")
	redisPort := getEnv("REDIS_PORT", "6379")
	redisDB := getEnv("REDIS_DB", "0")
	intRedisDB, err := strconv.Atoi(redisDB)
	if err != nil {
		return nil, err
	}
	development := getEnv("DEVELOPMENT", "local")

	pgUser, err := requiredEnv("POSTGRES_USER")
	if err != nil {
		return nil, err
	}

	pgPassword, err := requiredEnv("POSTGRES_PASSWORD")
	if err != nil {
		return nil, err
	}

	pgName, err := requiredEnv("POSTGRES_DB")
	if err != nil {
		return nil, err
	}

	jwtSecret, err := requiredEnv("JWT_SECRET")
	if err != nil {
		return nil, err
	}

	frontendURL := getEnv("FRONTEND_URL", "http://localhost:3000")

	cipherSecretKey, err := requiredEnv("CIPHER_SECRET_KEY")
	if err != nil {
		return nil, err
	}
	hmacSecretKey, err := requiredEnv("HMAC_SECRET_KEY")
	if err != nil {
		return nil, err
	}

	mailHost, err := requiredEnv("MAIL_HOST")
	if err != nil {
		return nil, err
	}

	mailPortStr, err := requiredEnv("MAIL_PORT")
	if err != nil {
		return nil, err
	}
	mailPort, err := strconv.Atoi(mailPortStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAIL_PORT: %w", err)
	}

	mailUser, err := requiredEnv("MAIL_USER")
	if err != nil {
		return nil, err
	}

	mailPass, err := requiredEnv("MAIL_PW")
	if err != nil {
		return nil, err
	}

	googleClientID, err := requiredEnv("GOOGLE_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	googleClientSecret, err := requiredEnv("GOOGLE_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	googleRedirectURL, err := requiredEnv("GOOGLE_REDIRECT_URL")
	if err != nil {
		return nil, err
	}

	redisPW, err := requiredEnv("REDIS_PASSWORD")
	if err != nil {
		return nil, err
	}

	awsRegion, err := requiredEnv("AWS_REGION")
	if err != nil {
		return nil, err
	}
	awsBucket, err := requiredEnv("AWS_IMAGE_BUCKET")
	if err != nil {
		return nil, err
	}

	return &Config{
		DB: DBConfig{
			PG: PGConfig{
				Host:     pgHost,
				Port:     pgPort,
				User:     pgUser,
				Name:     pgName,
				Password: pgPassword,
			},
			Redis: RedisConfig{
				Host:     redisHost,
				Port:     redisPort,
				DB:       intRedisDB,
				Password: redisPW,
			},
		},
		App: AppConfig{
			JWTSecret:       jwtSecret,
			Development:     development,
			FrontendURL:     frontendURL,
			CipherSecretKey: cipherSecretKey,
			HMAC_SECRET_KEY: hmacSecretKey,
			AWS: AwsConfig{
				Region: awsRegion,
				Bucket: awsBucket,
			},
		},
		Mail: MailConfig{
			Host: mailHost,
			Port: mailPort,
			User: mailUser,
			Pass: mailPass,
		},
		Google: GoogleConfig{
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			RedirectURL:  googleRedirectURL,
		},
	}, nil

}

func getEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}

	return val
}

func requiredEnv(key string) (string, error) {
	val := os.Getenv(key)

	if val == "" {
		return "", fmt.Errorf("%s must be set", key)
	}

	return val, nil
}
