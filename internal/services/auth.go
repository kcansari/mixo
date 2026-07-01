//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/oauth"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/session"
	"github.com/kcansari/mixo/internal/store"
)

var (
	ErrGoogleCodeRequired      = errors.New("googleOAuth code is required")
	ErrGoogleStateRequired     = errors.New("googleOAuth state is required")
	ErrRefreshTokenExpired     = errors.New("refresh token is expired")
	ErrRefreshTokenAlreadyUsed = errors.New("refresh token is already used")
	ErrInvalidTokenType        = errors.New("invalid token type")
)

type Auth struct {
	OAuthGoogle    OAuthGoogle
	UserStore      AuthUserStore
	SessionManager SessionManager
}

type OAuthGoogle interface {
	VerifyIDToken(ctx context.Context, token string) (*oauth.GoogleUserInfo, error)
}

type SessionManager interface {
	Create(ctx context.Context, userID uuid.UUID) (domain.Tokens, error)
	Destroy(ctx context.Context, userID uuid.UUID) error
	GetInfo(tokenString string) (session.SessionInfo, error)
	CheckIsRevokedRefreshToken(ctx context.Context, refreshToken string) (bool, error)
	RevokeRefreshToken(ctx context.Context, refreshToken string) error
}

type AuthUserStore interface {
	Create(ctx context.Context, user domain.UserCreate) (*domain.User, error)
	GetByProviderUserID(ctx context.Context, providerUserID string) (*domain.User, error)
}

func NewAuth(oauthGoogle OAuthGoogle, userStore AuthUserStore, sessionManager SessionManager) *Auth {
	return &Auth{
		OAuthGoogle:    oauthGoogle,
		UserStore:      userStore,
		SessionManager: sessionManager,
	}
}

func (a *Auth) AuthenticateGoogle(ctx context.Context, idToken string) (domain.Tokens, error) {

	user, err := a.OAuthGoogle.VerifyIDToken(ctx, idToken)
	if err != nil {
		return domain.Tokens{}, err
	}

	userID, err := a.findOrCreateGoogleUser(ctx, user)
	if err != nil {
		return domain.Tokens{}, err
	}

	tokens, err := a.SessionManager.Create(ctx, userID)
	if err != nil {
		return domain.Tokens{}, err
	}

	return tokens, nil
}

func (a *Auth) GetNewTokens(ctx context.Context, refreshToken string) (domain.Tokens, error) {

	sessionInfo, err := a.SessionManager.GetInfo(refreshToken)
	if err != nil {
		return domain.Tokens{}, err
	}

	if sessionInfo.IsExpired {
		if err := a.SessionManager.RevokeRefreshToken(ctx, refreshToken); err != nil {
			return domain.Tokens{}, err
		}
		return domain.Tokens{}, fmt.Errorf("refresh token is expired: user: %s %w", sessionInfo.Subject, ErrRefreshTokenExpired)
	}

	if sessionInfo.TokenType != security.TokenTypeRefresh {
		return domain.Tokens{}, fmt.Errorf("invalid token type: %s %w", sessionInfo.TokenType, ErrInvalidTokenType)
	}

	isRevoked, err := a.SessionManager.CheckIsRevokedRefreshToken(ctx, refreshToken)
	if err != nil {
		return domain.Tokens{}, err
	}
	if isRevoked {
		return domain.Tokens{}, fmt.Errorf("refresh token is already used: user: %s %w", sessionInfo.Subject, ErrRefreshTokenAlreadyUsed)
	}

	tokens, err := a.SessionManager.Create(ctx, uuid.MustParse(sessionInfo.Subject))

	if err != nil {
		return domain.Tokens{}, err
	}

	if err := a.SessionManager.RevokeRefreshToken(ctx, refreshToken); err != nil {
		return domain.Tokens{}, err
	}

	return tokens, nil
}

func (a *Auth) findOrCreateGoogleUser(ctx context.Context, user *oauth.GoogleUserInfo) (uuid.UUID, error) {
	existingUser, err := a.UserStore.GetByProviderUserID(ctx, user.ID)
	if err == nil {
		return existingUser.ID, nil
	}
	if !errors.Is(err, store.ErrUserNotFound) {
		return uuid.Nil, err
	}

	createdUser, err := a.UserStore.Create(ctx, domain.UserCreate{
		UserFields: domain.UserFields{
			Email:          user.Email,
			ProviderUserID: user.ID,
			EmailVerified:  user.EmailVerified,
			Name:           user.Name,
			GivenName:      user.GivenName,
			FamilyName:     user.FamilyName,
			Picture:        user.Picture,
		},
	})
	if err != nil {
		return uuid.Nil, err
	}
	return createdUser.ID, nil
}

func (a *Auth) Logout(ctx context.Context, userID uuid.UUID) error {

	if err := a.SessionManager.Destroy(ctx, userID); err != nil {
		return err
	}

	return nil
}
