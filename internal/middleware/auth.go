//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package middleware

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/httpx"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/session"
	"github.com/kcansari/mixo/internal/store"
)

type ContextKey string

const (
	ContextKeyUserID ContextKey = "userID"
)

const (
	DeleteCookieNow = -1
)

type AuthMiddleware struct {
	SessionManager SessionManager
}

type SessionManager interface {
	Create(ctx context.Context, userID uuid.UUID) (domain.Tokens, error)
	GetAccessToken(ctx context.Context, refreshToken string) (string, error)
	Destroy(ctx context.Context, userID uuid.UUID) error
	GetInfo(tokenString string) (session.SessionInfo, error)
	IsValidRefreshToken(ctx context.Context, refreshToken string) (bool, error)
	GetRefreshToken(ctx context.Context, userID uuid.UUID) (*domain.RefreshToken, error)
}

func NewAuth(sessionManager SessionManager) *AuthMiddleware {
	return &AuthMiddleware{
		SessionManager: sessionManager,
	}
}

func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := r.Cookie(string(security.TokenTypeAccess))
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}

		refreshToken, err := r.Cookie(string(security.TokenTypeRefresh))
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}

		claims, err := am.SessionManager.GetInfo(accessToken.Value)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}

		if claims.TokenType != security.TokenTypeAccess {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}

		if claims.IsExpired {

			claimsRefresh, err := am.SessionManager.GetInfo(refreshToken.Value)
			if err != nil {
				httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
				return
			}

			if claimsRefresh.TokenType != security.TokenTypeRefresh {
				httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
				return
			}

			if claimsRefresh.IsExpired {

				logoutErr := am.SessionManager.Destroy(r.Context(), uuid.MustParse(claimsRefresh.Subject))
				if logoutErr != nil {
					httpx.Render(w, r, httpx.FromError(r.Context(), logoutErr))
					return
				}
				SetAuthCookie(w, string(security.TokenTypeAccess), "", DeleteCookieNow)
				SetAuthCookie(w, string(security.TokenTypeRefresh), "", DeleteCookieNow)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}

			isValid, err := am.SessionManager.IsValidRefreshToken(r.Context(), refreshToken.Value)
			if err != nil {
				httpx.Render(w, r, httpx.FromError(r.Context(), err))
				return
			}
			if !isValid {
				httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
				return
			}

			// check refresh token will expire soon
			if claimsRefresh.ExpiresAt.Time.Before(time.Now().Add(3 * time.Hour)) {
				err = am.SessionManager.Destroy(r.Context(), uuid.MustParse(claimsRefresh.Subject))
				if err != nil {
					if errors.Is(err, store.ErrRefreshTokenNotFound) {

						refreshTokenInfo, err := am.SessionManager.GetRefreshToken(r.Context(), uuid.MustParse(claimsRefresh.Subject))
						if err != nil {
							httpx.Render(w, r, httpx.FromError(r.Context(), err))
							return
						}

						if refreshTokenInfo.RevokedAt.Before(time.Now().Add(20 * time.Second)) {
							ctx := context.WithValue(r.Context(), ContextKeyUserID, claimsRefresh.Subject)
							next.ServeHTTP(w, r.WithContext(ctx))
							return
						}

					}
					httpx.Render(w, r, httpx.FromError(r.Context(), err))
					return
				}

				tokens, err := am.SessionManager.Create(r.Context(), uuid.MustParse(claimsRefresh.Subject))
				if err != nil {
					httpx.Render(w, r, httpx.FromError(r.Context(), err))
					return
				}

				SetAuthCookie(w, string(security.TokenTypeRefresh), tokens.RefreshToken, int(domain.DefaultRefreshTokenExpiration/time.Second))
				SetAuthCookie(w, string(security.TokenTypeAccess), tokens.AccessToken, int(domain.DefaultAccessTokenExpiration/time.Second))

			} else {

				newAccessToken, err := am.SessionManager.GetAccessToken(r.Context(), refreshToken.Value)
				if err != nil {
					httpx.Render(w, r, httpx.FromError(r.Context(), err))
					return
				}

				SetAuthCookie(w, string(security.TokenTypeAccess), newAccessToken, int(domain.DefaultAccessTokenExpiration/time.Second))
			}

		}

		ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

func (am *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		// todo later

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(ContextKeyUserID).(string)
	return userID, ok
}

func SetAuthCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
