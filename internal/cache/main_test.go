package cache

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var testRedis *Redis

func TestMain(m *testing.M) {
	ctx := context.Background()

	redisContainer, err := testcontainers.Run(
		ctx,
		"redis:7.4-alpine",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("cache_test: starting Redis container: %v", err)
	}

	host, err := redisContainer.Host(ctx)
	if err != nil {
		log.Fatalf("cache_test: getting Redis host: %v", err)
	}

	port, err := redisContainer.MappedPort(ctx, "6379/tcp")
	if err != nil {
		log.Fatalf("cache_test: getting Redis port: %v", err)
	}

	testRedis, err = NewRedisClient(RedisConfig{
		Host:     host,
		Port:     port.Port(),
		Password: "test-password",
	})
	if err != nil {
		log.Fatalf("cache_test: creating Redis client: %v", err)
	}

	if err := testRedis.client.Ping(ctx).Err(); err != nil {
		log.Fatalf("cache_test: pinging Redis: %v", err)
	}

	code := m.Run()

	_ = testRedis.client.Close()
	_ = redisContainer.Terminate(ctx)

	os.Exit(code)
}

func resetRedis(t *testing.T) {
	t.Helper()

	if err := testRedis.client.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("resetRedis: %v", err)
	}
}
