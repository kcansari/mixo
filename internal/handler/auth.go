//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/httpx"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/serializer"
)

type Auth struct {
	AuthSvc     AuthSvc
	FrontendURL string
}

type AuthSvc interface {
	GetGoogleRedirectURL(ctx context.Context) (url string, err error)
	AuthenticateGoogle(ctx context.Context, code string, state string) (domain.Tokens, error)
	Logout(ctx context.Context, userID uuid.UUID) error
}

func NewAuth(auth Auth) *Auth {
	return &Auth{AuthSvc: auth.AuthSvc, FrontendURL: auth.FrontendURL}
}

func (a *Auth) Google(w http.ResponseWriter, r *http.Request) {
	url, err := a.AuthSvc.GetGoogleRedirectURL(r.Context())
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	http.Redirect(w, r, url, http.StatusFound)

}

func (a *Auth) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	data := &serializer.GoogleCallbackRequest{}

	if err := data.BindQuery(r); err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	if data.Error != "" {
		http.Redirect(w, r, a.FrontendURL, http.StatusFound)
		return
	}

	tokens, err := a.AuthSvc.AuthenticateGoogle(r.Context(), data.Code, data.State)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	middleware.SetAuthCookie(w, string(security.TokenTypeRefresh), tokens.RefreshToken, int(domain.DefaultRefreshTokenExpiration/time.Second))
	middleware.SetAuthCookie(w, string(security.TokenTypeAccess), tokens.AccessToken, int(domain.DefaultAccessTokenExpiration/time.Second))

	http.Redirect(w, r, a.FrontendURL, http.StatusFound)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {

	userID, ok := middleware.UserIDFromContext(r.Context())

	if !ok {
		httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
		return
	}

	userIDUUID, err := uuid.Parse(userID)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	err = a.AuthSvc.Logout(r.Context(), userIDUUID)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	middleware.SetAuthCookie(w, string(security.TokenTypeAccess), "", middleware.DeleteCookieNow)
	middleware.SetAuthCookie(w, string(security.TokenTypeRefresh), "", middleware.DeleteCookieNow)

	http.Redirect(w, r, a.FrontendURL, http.StatusFound)
}
