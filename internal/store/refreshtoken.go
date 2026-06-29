package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/ent"
	"github.com/kcansari/mixo/ent/refresh_token"
	"github.com/kcansari/mixo/ent/user"
	"github.com/kcansari/mixo/internal/domain"
)

var (
	ErrRefreshTokenAlreadyExists = errors.New("refresh token already exists")
	ErrRefreshTokenNotFound      = errors.New("refresh token not found")
)

type RefreshToken struct {
	client *ent.Client
}

func NewRefreshToken(client *ent.Client) *RefreshToken {
	return &RefreshToken{
		client: client,
	}
}

func (r *RefreshToken) Create(ctx context.Context, refreshToken string, userID uuid.UUID) error {
	_, err := r.client.Refresh_Token.Create().
		SetTokenHash(refreshToken).
		SetOwnerID(userID).
		Save(ctx)

	if err != nil {
		if ent.IsConstraintError(err) {
			nativeErr := errors.Unwrap(err)
			// Source: https://www.postgresql.org/docs/16/errcodes-appendix.html
			// 23505 = unique_violation
			if strings.Contains(nativeErr.Error(), "23505") {
				return fmt.Errorf("store.refresh_token.Create: refresh token: %s %w", refreshToken, ErrRefreshTokenAlreadyExists)
			}
		}
		return fmt.Errorf("store.refresh_token.Create: refresh token: %s %w", refreshToken, err)
	}

	return nil
}

func (r *RefreshToken) Revoke(ctx context.Context, userID uuid.UUID) error {
	affected, err := r.client.Refresh_Token.Update().
		Where(
			refresh_token.HasOwnerWith(user.IDEQ(userID)),
			refresh_token.RevokedAtIsNil(),
		).
		SetRevokedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("store.refresh_token.Revoke: user: %s %w", userID, err)
	}
	if affected == 0 {
		return fmt.Errorf("store.refresh_token.Revoke: user: %s %w", userID, ErrRefreshTokenNotFound)
	}

	return nil
}
func (r *RefreshToken) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	affected, err := r.client.Refresh_Token.Update().
		Where(
			refresh_token.TokenHashEQ(tokenHash),
		).
		SetRevokedAt(time.Now()).
		Save(ctx)

	if err != nil {
		return fmt.Errorf("store.refresh_token.RevokeByTokenHash: token hash: %s %w", tokenHash, err)
	}
	if affected == 0 {
		return fmt.Errorf("store.refresh_token.RevokeByTokenHash: token hash: %s %w", tokenHash, ErrRefreshTokenNotFound)
	}

	return nil
}

func (r *RefreshToken) GetByUserID(ctx context.Context, userID uuid.UUID) (*domain.RefreshToken, error) {
	res, err := r.client.Refresh_Token.Query().
		Where(
			refresh_token.HasOwnerWith(user.IDEQ(userID)),
			refresh_token.RevokedAtIsNil(),
		).
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("store.refresh_token.GetByUserID: user: %s %w", userID, ErrRefreshTokenNotFound)
		}
		return nil, fmt.Errorf("store.refresh_token.GetByUserID: user: %s %w", userID, err)
	}

	return &domain.RefreshToken{
		UserID:    userID,
		TokenHash: res.TokenHash,
		RevokedAt: res.RevokedAt,
		CreatedAt: res.CreatedAt,
	}, nil
}

func (r *RefreshToken) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.RefreshToken, error) {
	res, err := r.client.Refresh_Token.Query().
		Where(
			refresh_token.TokenHashEQ(tokenHash),
			refresh_token.RevokedAtIsNil(),
		).
		WithOwner().
		First(ctx)

	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("store.refresh_token.GetByTokenHash: token hash: %s %w", tokenHash, ErrRefreshTokenNotFound)
		}
		return nil, fmt.Errorf("store.refresh_token.GetByTokenHash: token hash: %s %w", tokenHash, err)
	}

	return &domain.RefreshToken{
		UserID:    res.Edges.Owner.ID,
		TokenHash: res.TokenHash,
		RevokedAt: res.RevokedAt,
		CreatedAt: res.CreatedAt,
	}, nil
}
