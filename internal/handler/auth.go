//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/kcansari/mixo/internal/httpx"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/serializer"
)

type Auth struct {
	AuthSvc     AuthSvc
	FrontendURL string
}

type AuthSvc interface {
	GetGoogleRedirectURL(ctx context.Context) (url string, err error)
	AuthenticateGoogle(ctx context.Context, code string, state string) (sessiondID string, err error)
	Logout(ctx context.Context, sessionID string) error
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

	sessionID, err := a.AuthSvc.AuthenticateGoogle(r.Context(), data.Code, data.State)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	cookie := &http.Cookie{
		Name:     "sid",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)

	http.Redirect(w, r, a.FrontendURL, http.StatusFound)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {

	userID, ok := middleware.UserIDFromContext(r.Context())

	if !ok {
		httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
		return
	}

	err := a.AuthSvc.Logout(r.Context(), userID)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	cookie := &http.Cookie{
		Name:     "sid",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}

	http.SetCookie(w, cookie)

	http.Redirect(w, r, a.FrontendURL, http.StatusFound)
}
