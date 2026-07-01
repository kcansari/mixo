//go:generate mockgen -source=auth.go -destination=mocks/auth_mock.go -package=mocks
package handler

import (
	"context"
	"net/http"

	"github.com/go-chi/render"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/httpx"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/serializer"
)

type Auth struct {
	AuthSvc AuthSvc
}

type AuthSvc interface {
	AuthenticateGoogle(ctx context.Context, idToken string) (domain.Tokens, error)
	Logout(ctx context.Context, userID uuid.UUID) error
	GetNewTokens(ctx context.Context, refreshToken string) (domain.Tokens, error)
}

func NewAuth(auth Auth) *Auth {
	return &Auth{AuthSvc: auth.AuthSvc}
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

	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) Verify(w http.ResponseWriter, r *http.Request) {
	data := &serializer.GoogleVerifyRequest{}

	if err := render.Bind(r, data); err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	tokens, err := a.AuthSvc.AuthenticateGoogle(r.Context(), data.Token)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	render.JSON(w, r, serializer.NewGoogleVerifyResponse(tokens.AccessToken, tokens.RefreshToken))
}

func (a *Auth) Refresh(w http.ResponseWriter, r *http.Request) {
	data := &serializer.RefreshRequest{}

	if err := render.Bind(r, data); err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	tokens, err := a.AuthSvc.GetNewTokens(r.Context(), data.RefreshToken)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}

	render.JSON(w, r, serializer.NewRefreshResponse(tokens.AccessToken, tokens.RefreshToken))
}
