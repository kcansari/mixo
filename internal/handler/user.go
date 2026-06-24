//go:generate mockgen -source=user.go -destination=mocks/user_mock.go -package=mocks
package handler

import (
	"context"
	"net/http"

	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/httpx"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/serializer"
)

type User struct {
	UserSvc UserSvc
}

type UserSvc interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}

func NewUser(user User) *User {
	return &User{UserSvc: user.UserSvc}
}

func (u *User) GetByID(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		httpx.Render(w, r, httpx.FromError(r.Context(), httpx.ErrUnauthorized))
		return
	}
	user, err := u.UserSvc.GetByID(r.Context(), userID)
	if err != nil {
		httpx.Render(w, r, httpx.FromError(r.Context(), err))
		return
	}
	httpx.Render(w, r, serializer.NewUserResponse(user))
}
