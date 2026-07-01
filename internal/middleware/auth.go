//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package middleware

import (
	"context"
	"net/http"

	"github.com/golang-jwt/jwt/v5/request"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/httpx"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/session"
)

type ContextKey string

const (
	ContextKeyUserID ContextKey = "userID"
)

type AuthMiddleware struct {
	SessionManager SessionManager
	JWTSvc         JWTSvc
}

type SessionManager interface {
	Create(ctx context.Context, userID uuid.UUID) (domain.Tokens, error)
	GetAccessToken(ctx context.Context, refreshToken string) (string, error)
	Destroy(ctx context.Context, userID uuid.UUID) error
	GetInfo(tokenString string) (session.SessionInfo, error)
	IsValidRefreshToken(ctx context.Context, refreshToken string) (bool, error)
	GetRefreshToken(ctx context.Context, userID uuid.UUID) (*domain.RefreshToken, error)
}

type JWTSvc interface {
	ExtractBearerToken(req *http.Request) (string, error)
}

func NewAuth(sessionManager SessionManager, jwtSvc JWTSvc) *AuthMiddleware {
	return &AuthMiddleware{
		SessionManager: sessionManager,
		JWTSvc:         jwtSvc,
	}
}

func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		token, err := am.JWTSvc.ExtractBearerToken(r)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), request.ErrNoTokenInRequest))
			return
		}

		sessionInfo, err := am.SessionManager.GetInfo(token)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), err))
			return
		}

		if sessionInfo.IsExpired {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}

		if sessionInfo.CustomClaims.TokenType != security.TokenTypeAccess {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}

		userID := sessionInfo.CustomClaims.Subject

		ctx := context.WithValue(r.Context(), ContextKeyUserID, userID)
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
