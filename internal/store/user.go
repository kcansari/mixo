package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/ent"
	"github.com/kcansari/mixo/ent/user"
	"github.com/kcansari/mixo/internal/domain"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserNotFound      = errors.New("user not found")
)

type Users struct {
	client *ent.Client
}

func NewUsers(client *ent.Client) *Users {
	return &Users{
		client: client,
	}
}

func (u *Users) Create(ctx context.Context, user domain.UserCreate) (*domain.User, error) {
	res, err := u.client.User.Create().
		SetEmail(user.Email).
		SetProviderUserID(user.ProviderUserID).
		SetVerifiedEmail(user.EmailVerified).
		SetName(user.Name).
		SetGivenName(user.GivenName).
		SetFamilyName(user.FamilyName).
		SetPicture(user.Picture).
		SetRefreshToken(user.RefreshToken).
		Save(ctx)

	if err != nil {
		if ent.IsConstraintError(err) {
			nativeErr := errors.Unwrap(err)
			// Source: https://www.postgresql.org/docs/16/errcodes-appendix.html
			// 23505 = unique_violation
			if strings.Contains(nativeErr.Error(), "23505") {
				return nil, fmt.Errorf("store.users.Create: user: %s %w", res, ErrUserAlreadyExists)
			}
		}
		return nil, fmt.Errorf("store.users.Create: user: %s %w", res, err)
	}
	return toDomainUser(res), nil

}

func (u *Users) GetByProviderUserID(ctx context.Context, providerUserID string) (*domain.User, error) {
	usr, err := u.client.User.Query().Where(user.ProviderUserIDEQ(providerUserID)).First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("store.users.GetByProviderUserID: user: %s %w", providerUserID, ErrUserNotFound)
		}
		return nil, fmt.Errorf("store.users.GetByProviderUserID: user: %s %w", providerUserID, err)
	}
	return toDomainUser(usr), nil
}

func (u *Users) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	usr, err := u.client.User.Query().Where(user.IDEQ(id)).First(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("store.users.GetByID: user: %s %w", id, ErrUserNotFound)
		}
		return nil, fmt.Errorf("store.users.GetByID: user: %s %w", id, err)
	}
	return toDomainUser(usr), nil
}

func toDomainUser(usr *ent.User) *domain.User {
	if usr == nil {
		return nil
	}

	return &domain.User{
		ID: usr.ID,
		UserFields: domain.UserFields{
			Email:          usr.Email,
			ProviderUserID: usr.ProviderUserID,
			EmailVerified:  usr.VerifiedEmail,
			Name:           usr.Name,
			GivenName:      usr.GivenName,
			FamilyName:     usr.FamilyName,
			Picture:        usr.Picture,
			IsAdmin:        usr.IsAdmin,
		},
	}
}
