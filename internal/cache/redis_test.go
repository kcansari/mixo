package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewRedisClient(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config  RedisConfig
		wantErr error
	}{
		"creates client with configured options": {
			config: RedisConfig{
				Host:     "redis.example.com",
				Port:     "6380",
				Password: "password",
				DB:       2,
			},
		},
		"returns error when host is empty": {
			config: RedisConfig{
				Port:     "6380",
				Password: "password",
			},
			wantErr: ErrRedisHostRequired,
		},
		"returns error when port is empty": {
			config: RedisConfig{
				Host:     "redis.example.com",
				Password: "password",
			},
			wantErr: ErrRedisPortRequired,
		},
		"returns error when password is empty": {
			config: RedisConfig{
				Host: "redis.example.com",
				Port: "6380",
			},
			wantErr: ErrRedisPasswordEmpty,
		},
		"returns error when database is negative": {
			config: RedisConfig{
				Host:     "redis.example.com",
				Port:     "6380",
				Password: "password",
				DB:       -1,
			},
			wantErr: ErrRedisDBNegative,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := NewRedisClient(tt.config)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewRedisClient() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if got != nil {
					t.Errorf("NewRedisClient() = %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("NewRedisClient() = nil, want client")
			}
			t.Cleanup(func() {
				if err := got.client.Close(); err != nil {
					t.Errorf("Close() error = %v", err)
				}
			})

			options := got.client.Options()
			wantAddr := tt.config.Host + ":" + tt.config.Port
			if options.Addr != wantAddr {
				t.Errorf("NewRedisClient() address = %q, want %q", options.Addr, wantAddr)
			}
			if options.Password != tt.config.Password {
				t.Errorf("NewRedisClient() password = %q, want %q", options.Password, tt.config.Password)
			}
			if options.DB != tt.config.DB {
				t.Errorf("NewRedisClient() database = %d, want %d", options.DB, tt.config.DB)
			}
		})
	}
}

func TestRedisSet(t *testing.T) {
	tests := []struct {
		name          string
		cancelContext bool
		wantErrIs     error
	}{
		{
			name: "sets a value",
		},
		{
			name:          "returns error when context is canceled",
			cancelContext: true,
			wantErrIs:     context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRedis(t)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			err := testRedis.Set(ctx, "key", "value", 0)
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("Set() error = %v, want %v", err, tt.wantErrIs)
			}

			if tt.wantErrIs == nil {
				got, err := testRedis.client.Get(context.Background(), "key").Result()
				if err != nil {
					t.Fatalf("Redis GET error = %v", err)
				}
				if got != "value" {
					t.Errorf("Redis GET value = %q, want %q", got, "value")
				}
			}
		})
	}
}

func TestRedisGet(t *testing.T) {
	tests := []struct {
		name          string
		before        func(t *testing.T)
		cancelContext bool
		want          string
		wantErrIs     error
	}{
		{
			name: "gets an existing value",
			before: func(t *testing.T) {
				setRedisValue(t, "key", "value", 0)
			},
			want: "value",
		},
		{
			name:      "returns error when key does not exist",
			wantErrIs: ErrRedisKeyDoesNotExist,
		},
		{
			name:          "returns error when context is canceled",
			cancelContext: true,
			wantErrIs:     context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRedis(t)
			if tt.before != nil {
				tt.before(t)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			got, err := testRedis.Get(ctx, "key")
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("Get() error = %v, want %v", err, tt.wantErrIs)
			}
			if got != tt.want {
				t.Errorf("Get() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedisDelete(t *testing.T) {
	tests := []struct {
		name          string
		before        func(t *testing.T)
		cancelContext bool
		wantErrIs     error
	}{
		{
			name: "deletes an existing key",
			before: func(t *testing.T) {
				setRedisValue(t, "key", "value", 0)
			},
		},
		{
			name: "deleting a missing key succeeds",
		},
		{
			name:          "returns error when context is canceled",
			cancelContext: true,
			wantErrIs:     context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRedis(t)
			if tt.before != nil {
				tt.before(t)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			err := testRedis.Delete(ctx, "key")
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("Delete() error = %v, want %v", err, tt.wantErrIs)
			}

			if tt.wantErrIs == nil {
				exists, err := testRedis.client.Exists(context.Background(), "key").Result()
				if err != nil {
					t.Fatalf("Redis EXISTS error = %v", err)
				}
				if exists != 0 {
					t.Errorf("Redis EXISTS = %d, want 0", exists)
				}
			}
		})
	}
}

func TestRedisSetExpiration(t *testing.T) {
	resetRedis(t)

	const key = "expiring-key"
	if err := testRedis.Set(context.Background(), key, "value", 100*time.Millisecond); err != nil {
		t.Fatalf("Set() error = %v, want nil", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, err := testRedis.Get(context.Background(), key)
		if errors.Is(err, ErrRedisKeyDoesNotExist) {
			return
		}
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("key %q did not expire before deadline", key)
}

func TestKeyCreator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		prefix  string
		key     string
		want    string
		wantErr error
	}{
		{
			name:   "joins prefix and key",
			prefix: "oauth:google:",
			key:    "state",
			want:   "oauth:google:state",
		},
		{
			name:    "returns error for empty prefix",
			prefix:  "",
			key:     "state",
			wantErr: ErrRedisKeyPrefixEmpty,
		},
		{
			name:    "returns error for empty key",
			prefix:  "oauth:google:",
			key:     "",
			wantErr: ErrRedisKeyEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := testRedis.KeyCreator(tt.prefix, tt.key)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("KeyCreator(%q, %q) error = %v, want %v", tt.prefix, tt.key, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("KeyCreator(%q, %q) = %q, want %q", tt.prefix, tt.key, got, tt.want)
			}
		})
	}
}

func setRedisValue(t *testing.T, key string, value any, expiration time.Duration) {
	t.Helper()

	if err := testRedis.Set(context.Background(), key, value, expiration); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
}

func TestRedisTTL(t *testing.T) {
	tests := []struct {
		name          string
		key           string
		before        func(t *testing.T)
		cancelContext bool
		want          time.Duration
		wantErrIs     error
	}{
		{
			name: "key exist but has no TTL",
			key:  "key",
			before: func(t *testing.T) {
				setRedisValue(t, "key", "value", 0)
			},
			want: -1 * time.Nanosecond, // key exist but no ttl
		},
		{
			name: "key exist and has TTL",
			key:  "key",
			before: func(t *testing.T) {
				setRedisValue(t, "key", "value", 10*time.Minute)
			},
			want: 10 * time.Minute,
		},
		{
			name:      "key does not exist",
			key:       "not-exist-key",
			want:      -2 * time.Nanosecond, // key does not exist
			wantErrIs: ErrRedisKeyDoesNotExist,
		},
		{
			name:      "empty key",
			key:       "",
			wantErrIs: ErrRedisKeyEmpty,
		},
		{
			name:          "returns error when context is canceled",
			key:           "key",
			cancelContext: true,
			wantErrIs:     context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRedis(t)
			if tt.before != nil {
				tt.before(t)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			got, err := testRedis.TTL(ctx, tt.key)
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("TTL() error = %v, want %v", err, tt.wantErrIs)
			}
			if got != tt.want {
				t.Errorf("TTL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedisExpire(t *testing.T) {
	key := "key"
	tests := []struct {
		name          string
		key           string
		expiration    time.Duration
		before        func(t *testing.T)
		cancelContext bool
		wantErrIs     error
		want          bool
	}{
		{
			name:       "valid key and valid expiration",
			key:        key,
			expiration: 1 * time.Hour,
			before: func(t *testing.T) {
				setRedisValue(t, key, "value", 0)
			},
			wantErrIs: nil,
			want:      true,
		},
		{
			name:      "empty key",
			key:       "  ",
			wantErrIs: ErrRedisKeyEmpty,
			want:      false,
		},
		{
			name:      "not exist key",
			key:       "does-not-exist",
			wantErrIs: ErrRedisKeyDoesNotExist,
			want:      false,
		},
		{
			name: "negative expiration",
			key:  key,
			before: func(t *testing.T) {
				setRedisValue(t, key, "value", 0)
			},
			expiration: -1 * time.Hour,
			wantErrIs:  ErrRedisExpirationNegative,
			want:       false,
		},
		{
			name:          "returns error when context is canceled",
			key:           key,
			cancelContext: true,
			wantErrIs:     context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRedis(t)
			if tt.before != nil {
				tt.before(t)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			ok, err := testRedis.Expire(ctx, tt.key, tt.expiration)
			if !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("Expire() error = %v, want %v", err, tt.wantErrIs)
			}
			if ok != tt.want {
				t.Errorf("Expire() = %v, want %v", ok, tt.want)
			}
		})
	}
}
