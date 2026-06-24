//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/oauth"
	"github.com/kcansari/mixo/internal/store"
	"golang.org/x/oauth2"
)

var (
	ErrGoogleCodeRequired  = errors.New("googleOAuth code is required")
	ErrGoogleStateRequired = errors.New("googleOAuth state is required")
)

const (
	outhGoogleTag = "outh:google:"
)

type Auth struct {
	OAuthGoogle    OAuthGoogle
	Cache          Cache
	UserStore      AuthUserStore
	Chiper         Chiper
	SessionManager SessionManager
}

type OAuthGoogle interface {
	GetRedirectURL() (verifier, state, url string)
	Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error)
	GetUserInfo(ctx context.Context, token *oauth2.Token) (user oauth.GoogleUserInfo, err error)
}

type Cache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	KeyCreator(prefix string, key string) (string, error)
}

type Chiper interface {
	Encrypt(text string) (string, error)
	Decrypt(text string) (string, error)
}

type SessionManager interface {
	Create(ctx context.Context, value string) (string, error)
	Destroy(ctx context.Context, sid string) error
	Get(ctx context.Context, sid string) (string, error)
}

type AuthUserStore interface {
	Create(ctx context.Context, user domain.UserCreate) (*domain.User, error)
	GetByProviderUserID(ctx context.Context, providerUserID string) (*domain.User, error)
}

func NewAuth(oauthGoogle OAuthGoogle, cache Cache, userStore AuthUserStore, chiper Chiper, sessionManager SessionManager) *Auth {
	return &Auth{
		OAuthGoogle:    oauthGoogle,
		Cache:          cache,
		UserStore:      userStore,
		Chiper:         chiper,
		SessionManager: sessionManager,
	}
}

func (a *Auth) GetGoogleRedirectURL(ctx context.Context) (url string, err error) {
	verifier, state, url := a.OAuthGoogle.GetRedirectURL()
	key, err := a.Cache.KeyCreator(outhGoogleTag, state)
	if err != nil {
		return "", err
	}

	err = a.Cache.Set(ctx, key, verifier, 5*time.Minute)
	if err != nil {
		return "", err
	}

	return url, nil
}

func (a *Auth) AuthenticateGoogle(ctx context.Context, code string, state string) (sessionID string, err error) {

	if strings.TrimSpace(code) == "" {
		return "", ErrGoogleCodeRequired
	}
	if strings.TrimSpace(state) == "" {
		return "", ErrGoogleStateRequired
	}

	key, err := a.Cache.KeyCreator(outhGoogleTag, state)
	if err != nil {
		return "", err
	}

	verifier, err := a.Cache.Get(ctx, key)
	if err != nil {
		return "", err
	}

	err = a.Cache.Delete(ctx, key)
	if err != nil {
		return "", err
	}

	token, err := a.OAuthGoogle.Exchange(ctx, code, verifier)
	if err != nil {
		return "", err
	}

	user, err := a.OAuthGoogle.GetUserInfo(ctx, token)
	if err != nil {
		return "", err
	}

	existingUser, err := a.UserStore.GetByProviderUserID(ctx, user.ID)
	if err != nil {
		if !errors.Is(err, store.ErrUserNotFound) {
			return "", err
		}
	}

	var userID uuid.UUID

	if existingUser == nil {

		encryptedRefreshToken, err := a.Chiper.Encrypt(token.RefreshToken)
		if err != nil {
			return "", err
		}

		userStore, err := a.UserStore.Create(ctx, domain.UserCreate{
			UserFields: domain.UserFields{
				Email:          user.Email,
				ProviderUserID: user.ID,
				EmailVerified:  user.EmailVerified,
				Name:           user.Name,
				GivenName:      user.GivenName,
				FamilyName:     user.FamilyName,
				Picture:        user.Picture,
			},
			RefreshToken: encryptedRefreshToken,
		})
		if err != nil {
			return "", err
		}
		userID = userStore.ID

	} else {
		userID = existingUser.ID
	}

	sessionID, err = a.SessionManager.Create(ctx, userID.String())
	if err != nil {
		return "", err
	}

	return sessionID, nil
}

func (a *Auth) Logout(ctx context.Context, sessionID string) error {

	if err := a.SessionManager.Destroy(ctx, sessionID); err != nil {
		return err
	}

	return nil
}
