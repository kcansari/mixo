//go:generate mockgen -source=session.go -destination=mock_session_test.go -package=security
package security

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

const DefaultSessionExpiration = 30 * 24 * time.Hour
const SessionPrefix = "session:"

var ErrSessionIDRequired = errors.New("session id is required")

type Session struct {
	Cache Cache
	HMAC  HMAC
}

type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	KeyCreator(prefix string, key string) (string, error)
	TTL(ctx context.Context, key string) (time.Duration, error)
	Expire(ctx context.Context, key string, expiration time.Duration) (bool, error)
}

type HMAC interface {
	Sign(data string) string
}

func NewSession(cache Cache, hmac HMAC) *Session {
	return &Session{
		Cache: cache,
		HMAC:  hmac,
	}
}

func (s *Session) Create(ctx context.Context, value string) (string, error) {
	sid := generateSessionID()

	key, err := s.getKey(sid)
	if err != nil {
		return "", fmt.Errorf("security.session.Create: sid: %s, value: %s, error: %w", sid, value, err)
	}

	if err := s.Cache.Set(ctx, key, value, DefaultSessionExpiration); err != nil {
		return "", fmt.Errorf("security.session.Create: sid: %s, value: %s, error: %w", sid, value, err)
	}

	return sid, nil
}

func (s *Session) Get(ctx context.Context, sid string) (string, error) {
	key, err := s.getKey(sid)
	if err != nil {
		return "", fmt.Errorf("security.session.Get: sid: %s, error: %w", sid, err)
	}

	value, err := s.Cache.Get(ctx, key)
	if err != nil {
		return "", fmt.Errorf("security.session.Get: sid: %s, error: %w", sid, err)
	}

	return value, nil
}

func (s *Session) Destroy(ctx context.Context, sid string) error {
	key, err := s.getKey(sid)
	if err != nil {
		return fmt.Errorf("security.session.Destroy: sid: %s, error: %w", sid, err)
	}

	err = s.Cache.Delete(ctx, key)
	if err != nil {
		return fmt.Errorf("security.session.Destroy: sid: %s, error: %w", sid, err)
	}

	return nil
}

func (s *Session) ShouldExtend(ctx context.Context, sid string) (bool, error) {

	key, err := s.getKey(sid)
	if err != nil {
		return false, fmt.Errorf("security.session.ShouldExtend: sid: %s, error: %w", sid, err)
	}

	ttl, err := s.Cache.TTL(ctx, key)
	if err != nil {
		return false, fmt.Errorf("security.session.ShouldExtend: sid: %s, error: %w", sid, err)
	}

	return ttl <= DefaultSessionExpiration/2, nil
}

func (s *Session) Extend(ctx context.Context, sid string) error {
	key, err := s.getKey(sid)
	if err != nil {
		return fmt.Errorf("security.session.Extend: sid: %s, error: %w", sid, err)
	}

	ok, err := s.Cache.Expire(ctx, key, DefaultSessionExpiration)
	if err != nil {
		return fmt.Errorf("security.session.Extend: sid: %s, error: %w", sid, err)
	}

	if !ok {
		return fmt.Errorf("security.session.Extend: sid: %s, error: %w", sid, ErrSessionNotFound)
	}

	return nil
}

func generateSessionID() string {
	b := make([]byte, 32)

	_, _ = io.ReadFull(rand.Reader, b)

	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Session) getKey(sid string) (string, error) {
	if strings.TrimSpace(sid) == "" {
		return "", fmt.Errorf("security.session.getKey: sid: %s, error: %w", sid, ErrSessionIDRequired)
	}
	signed := s.HMAC.Sign(sid)
	return s.Cache.KeyCreator(SessionPrefix, signed)
}
