//go:generate mockgen -source=user.go -destination=mocks/user_mock.go -package=mocks
package services

import (
	"context"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
)

type User struct {
	UserStore UserStore
}

type UserStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

func NewUser(userStore UserStore) *User {
	return &User{
		UserStore: userStore,
	}
}

func (u *User) GetByID(ctx context.Context, id string) (*domain.User, error) {
	uuidID, err := uuid.Parse(id)
	if err != nil {
		return nil, err
	}
	user, err := u.UserStore.GetByID(ctx, uuidID)
	if err != nil {
		return nil, err
	}
	return user, nil
}
