package cache

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrRedisKeyDoesNotExist = errors.New("redis key does not exist")
	ErrRedisHostRequired    = errors.New("redis host is required")
	ErrRedisPortRequired    = errors.New("redis port is required")
	ErrRedisPasswordEmpty   = errors.New("redis password is empty")
	ErrRedisDBNegative      = errors.New("redis db must be positive")

	ErrRedisKeyPrefixEmpty     = errors.New("redis key prefix is empty")
	ErrRedisKeyEmpty           = errors.New("redis key is empty")
	ErrRedisExpirationNegative = errors.New("redis expiration must be positive")
)

type Redis struct {
	client *redis.Client
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

func NewRedisClient(config RedisConfig) (*Redis, error) {

	if strings.TrimSpace(config.Host) == "" {
		return nil, ErrRedisHostRequired
	}
	if strings.TrimSpace(config.Port) == "" {
		return nil, ErrRedisPortRequired
	}

	if strings.TrimSpace(config.Password) == "" {
		return nil, ErrRedisPasswordEmpty
	}

	if config.DB < 0 {
		return nil, ErrRedisDBNegative
	}

	return &Redis{
		client: redis.NewClient(&redis.Options{
			Addr:     net.JoinHostPort(config.Host, config.Port),
			Password: config.Password,
			DB:       config.DB,
		}),
	}, nil
}

func (r *Redis) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	err := r.client.Set(ctx, key, value, expiration).Err()
	if err != nil {
		return fmt.Errorf("cache.redis.Set: key: %s, value: %v, error: %w", key, value, err)
	}
	return nil
}

func (r *Redis) Get(ctx context.Context, key string) (string, error) {
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", fmt.Errorf("cache.redis.Get: key: %s, error: %w", key, ErrRedisKeyDoesNotExist)
		}
		return "", fmt.Errorf("cache.redis.Get: key: %s, error: %w", key, err)
	}
	return val, nil
}

func (r *Redis) Delete(ctx context.Context, key string) error {
	err := r.client.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("cache.redis.Delete: key: %s, error: %w", key, err)
	}
	return nil
}

func (r *Redis) TTL(ctx context.Context, key string) (time.Duration, error) {

	if strings.TrimSpace(key) == "" {
		return 0, fmt.Errorf("cache.redis.TTL: key:%s %w", key, ErrRedisKeyEmpty)
	}

	ttl, err := r.client.TTL(ctx, key).Result()

	if ttl == -2*time.Nanosecond {
		return -2 * time.Nanosecond, fmt.Errorf("cache.redis.TTL: key: %s, error: %w", key, ErrRedisKeyDoesNotExist)
	}

	if err != nil {
		return 0, fmt.Errorf("cache.redis.TTL: key: %s, error: %w", key, err)
	}
	return ttl, nil
}

func (r *Redis) Expire(ctx context.Context, key string, expiration time.Duration) (bool, error) {
	if strings.TrimSpace(key) == "" {
		return false, fmt.Errorf("cache.redis.Expire: key:%s %w", key, ErrRedisKeyEmpty)
	}
	if expiration < 0 {
		return false, fmt.Errorf("cache.redis.Expire: key:%s %w", key, ErrRedisExpirationNegative)
	}
	ok, err := r.client.Expire(ctx, key, expiration).Result()
	if err != nil {
		return false, fmt.Errorf("cache.redis.Expire: key: %s, error: %w", key, err)
	}
	if !ok {
		return false, fmt.Errorf("cache.redis.Expire: key: %s, error: %w", key, ErrRedisKeyDoesNotExist)
	}
	return true, nil
}

func (r *Redis) KeyCreator(prefix string, key string) (string, error) {
	if strings.TrimSpace(prefix) == "" {
		return "", fmt.Errorf("cache.redis.KeyCreator: prefix:%s %w", prefix, ErrRedisKeyPrefixEmpty)
	}
	if strings.TrimSpace(key) == "" {
		return "", fmt.Errorf("cache.redis.KeyCreator: key:%s %w", key, ErrRedisKeyEmpty)
	}
	return prefix + key, nil
}
