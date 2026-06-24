//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/httpx"
)

type ContextKey string

const (
	ContextKeyUserID ContextKey = "userID"
)

type AuthMiddleware struct {
	SessionManager SessionManager
	UserSvc        UserSvc
}

type SessionManager interface {
	Create(ctx context.Context, value string) (string, error)
	Get(ctx context.Context, id string) (string, error)
	Destroy(ctx context.Context, id string) error
	Extend(ctx context.Context, sid string) error
	ShouldExtend(ctx context.Context, sid string) (bool, error)
}

type UserSvc interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

func NewAuth(sessionManager SessionManager, userSvc UserSvc) *AuthMiddleware {
	return &AuthMiddleware{
		SessionManager: sessionManager,
		UserSvc:        userSvc,
	}
}

func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("sid")
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}
		userID, err := am.SessionManager.Get(r.Context(), sessionID.Value)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}
		shouldExtend, err := am.SessionManager.ShouldExtend(r.Context(), sessionID.Value)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}
		if shouldExtend {
			if err := am.SessionManager.Extend(r.Context(), sessionID.Value); err != nil {
				slog.Error("failed to extend session", "error", err)
			}
		}
		ctx := context.WithValue(r.Context(), ContextKeyUserID, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}

func (am *AuthMiddleware) RequireAdmin(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		sessionID, err := r.Cookie("sid")
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}
		userID, err := am.SessionManager.Get(r.Context(), sessionID.Value)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}
		user, err := am.UserSvc.GetByID(r.Context(), userID)
		if err != nil {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
			return
		}
		if !user.IsAdmin {
			httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrForbidden))
			return
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(ContextKeyUserID).(string)
	return userID, ok
}
