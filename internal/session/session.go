//go:generate mockgen -source=session.go -destination=mock_session_test.go -package=session
package session

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/security"
)

var (
	ErrSessionNotFound   = errors.New("session not found")
	ErrSessionIDRequired = errors.New("session id is required")
)

type SessionInfo struct {
	IsExpired bool
	*security.CustomClaims
}

type Session struct {
	JWTSvc     JWTSvc
	HMACSvc    HMACSvc
	TokenStore TokenStore
}

type JWTSvc interface {
	GenerateJWT(userID uuid.UUID, exp time.Time, tokenType security.TokenType) (string, error)
	ParseJWT(t string) (*security.CustomClaims, error)
}

type TokenStore interface {
	Create(ctx context.Context, refreshToken string, userID uuid.UUID) error
	Revoke(ctx context.Context, userID uuid.UUID) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error)
}

type HMACSvc interface {
	Sign(data string) (hash string)
}

// NewSession creates a new session
func NewSession(jwtSvc JWTSvc, hmacSvc HMACSvc, tokenStore TokenStore) *Session {
	return &Session{
		JWTSvc:     jwtSvc,
		HMACSvc:    hmacSvc,
		TokenStore: tokenStore,
	}
}

// Create creates a new session for the given user ID
func (s *Session) Create(ctx context.Context, userID uuid.UUID) (domain.Tokens, error) {

	accessToken, err := s.JWTSvc.GenerateJWT(userID, time.Now().Add(domain.DefaultAccessTokenExpiration), security.TokenTypeAccess)
	if err != nil {
		return domain.Tokens{}, err
	}

	refreshToken, err := s.JWTSvc.GenerateJWT(userID, time.Now().Add(domain.DefaultRefreshTokenExpiration), security.TokenTypeRefresh)
	if err != nil {
		return domain.Tokens{}, err
	}

	hashedRefreshToken := s.HMACSvc.Sign(refreshToken)

	err = s.TokenStore.Create(ctx, hashedRefreshToken, userID)
	if err != nil {
		return domain.Tokens{}, err
	}

	return domain.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Destroy invalidates the session for the given user ID
func (s *Session) Destroy(ctx context.Context, userID uuid.UUID) error {
	err := s.TokenStore.Revoke(ctx, userID)
	if err != nil {
		return err
	}
	return nil
}

// GetAccesToken generates a new access token for the given refresh token
func (s *Session) GetAccesToken(ctx context.Context, refreshToken string) (string, error) {

	hashedRefreshToken := s.HMACSvc.Sign(refreshToken)

	token, err := s.TokenStore.GetByTokenHash(ctx, hashedRefreshToken)
	if err != nil {
		return "", err
	}

	accessToken, err := s.JWTSvc.GenerateJWT(token.UserID, time.Now().Add(domain.DefaultAccessTokenExpiration), security.TokenTypeAccess)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func (s *Session) GetInfo(tokenString string) (SessionInfo, error) {
	claims, err := s.JWTSvc.ParseJWT(tokenString)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {

			return SessionInfo{
				IsExpired:    true,
				CustomClaims: claims,
			}, nil
		}
		return SessionInfo{}, err
	}

	return SessionInfo{
		CustomClaims: claims,
	}, nil
}
