package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/ent/refresh_token"
	"github.com/kcansari/mixo/internal/domain"
)

func resetRefreshTokens(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := testClient.Refresh_Token.Delete().Exec(ctx); err != nil {
		t.Fatalf("resetRefreshTokens: %v", err)
	}
	resetUsers(t)
}

func seedRefreshTokenUser(t *testing.T) uuid.UUID {
	t.Helper()
	providerID := uuid.NewString()
	return seedUser(t, NewUsers(testClient), domain.UserCreate{
		UserFields: domain.UserFields{
			Email:          providerID + "@example.com",
			EmailVerified:  true,
			ProviderUserID: providerID,
			Name:           "test user name",
			GivenName:      "test given name",
			FamilyName:     "test family name",
			Picture:        "test-user-picture",
		},
	})
}

func TestRefreshToken_Create(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		tokenHash     string
		before        func(t *testing.T, userID uuid.UUID)
		cancelContext bool
		wantErr       error
	}{
		{
			name:      "stores a refresh token hash for a user",
			tokenHash: "refresh-token-hash",
		},
		{
			name:      "returns an error when the refresh token already exists",
			tokenHash: "duplicate-refresh-token-hash",
			before: func(t *testing.T, userID uuid.UUID) {
				t.Helper()
				if err := NewRefreshToken(testClient).Create(ctx, "duplicate-refresh-token-hash", userID); err != nil {
					t.Fatalf("Create() setup error = %v", err)
				}
			},
			wantErr: ErrRefreshTokenAlreadyExists,
		},
		{
			name:          "returns an error when context is canceled",
			tokenHash:     "canceled-refresh-token-hash",
			cancelContext: true,
			wantErr:       context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRefreshTokens(t)
			userID := seedRefreshTokenUser(t)

			if tt.before != nil {
				tt.before(t, userID)
			}

			testCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			err := NewRefreshToken(testClient).Create(testCtx, tt.tokenHash, userID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Create() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			got, err := testClient.Refresh_Token.Query().
				Where(refresh_token.TokenHashEQ(tt.tokenHash)).
				Only(ctx)
			if err != nil {
				t.Fatalf("query refresh token: %v", err)
			}
			if got.TokenHash != tt.tokenHash {
				t.Errorf("Create() token hash = %q, want %q", got.TokenHash, tt.tokenHash)
			}
			if got.RevokedAt != nil {
				t.Errorf("Create() revoked at = %v, want nil", got.RevokedAt)
			}

			owner, err := got.QueryOwner().Only(ctx)
			if err != nil {
				t.Fatalf("query refresh token owner: %v", err)
			}
			if owner.ID != userID {
				t.Errorf("Create() owner ID = %v, want %v", owner.ID, userID)
			}
		})
	}
}

func TestRefreshToken_Revoke(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		before  func(t *testing.T, userID uuid.UUID, tokenHash string)
		wantErr error
	}{
		{
			name: "revokes active refresh tokens for a user",
			before: func(t *testing.T, userID uuid.UUID, tokenHash string) {
				t.Helper()
				if err := NewRefreshToken(testClient).Create(ctx, tokenHash, userID); err != nil {
					t.Fatalf("Create() setup error = %v", err)
				}
			},
		},
		{
			name:    "returns not found when the user has no active refresh token",
			wantErr: ErrRefreshTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRefreshTokens(t)
			userID := seedRefreshTokenUser(t)
			tokenHash := uuid.NewString()

			if tt.before != nil {
				tt.before(t, userID, tokenHash)
			}

			err := NewRefreshToken(testClient).Revoke(ctx, userID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Revoke() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			got, err := testClient.Refresh_Token.Query().
				Where(refresh_token.TokenHashEQ(tokenHash)).
				Only(ctx)
			if err != nil {
				t.Fatalf("query refresh token: %v", err)
			}
			if got.RevokedAt == nil {
				t.Error("Revoke() revoked at is nil, want a timestamp")
			}
		})
	}
}

func TestRefreshToken_GetByUserID(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		tokenHash string
		before    func(t *testing.T, userID uuid.UUID, tokenHash string)
		wantErr   error
	}{
		{
			name:      "returns the active refresh token for a user",
			tokenHash: "active-refresh-token-hash",
			before: func(t *testing.T, userID uuid.UUID, tokenHash string) {
				t.Helper()
				if err := NewRefreshToken(testClient).Create(ctx, tokenHash, userID); err != nil {
					t.Fatalf("Create() setup error = %v", err)
				}
			},
		},
		{
			name:    "returns not found when the user has no refresh token",
			wantErr: ErrRefreshTokenNotFound,
		},
		{
			name:      "returns not found when the refresh token is revoked",
			tokenHash: "revoked-refresh-token-hash",
			before: func(t *testing.T, userID uuid.UUID, tokenHash string) {
				t.Helper()
				refreshTokenStore := NewRefreshToken(testClient)
				if err := refreshTokenStore.Create(ctx, tokenHash, userID); err != nil {
					t.Fatalf("Create() setup error = %v", err)
				}
				if err := refreshTokenStore.Revoke(ctx, userID); err != nil {
					t.Fatalf("Revoke() setup error = %v", err)
				}
			},
			wantErr: ErrRefreshTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRefreshTokens(t)
			userID := seedRefreshTokenUser(t)

			if tt.before != nil {
				tt.before(t, userID, tt.tokenHash)
			}

			got, err := NewRefreshToken(testClient).GetByUserID(ctx, userID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByUserID() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if got != nil {
					t.Errorf("GetByUserID() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("GetByUserID() = nil, want refresh token")
			}
			if got.UserID != userID {
				t.Errorf("GetByUserID() user ID = %v, want %v", got.UserID, userID)
			}
			if got.TokenHash != tt.tokenHash {
				t.Errorf("GetByUserID() token hash = %q, want %q", got.TokenHash, tt.tokenHash)
			}
			if got.RevokedAt != nil {
				t.Errorf("GetByUserID() revoked at = %v, want nil", got.RevokedAt)
			}
			if got.CreatedAt.IsZero() {
				t.Error("GetByUserID() created at is zero, want timestamp")
			}
		})
	}
}

func TestRefreshToken_GetByTokenHash(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		tokenHash string
		before    func(t *testing.T, userID uuid.UUID, tokenHash string)
		wantErr   error
	}{
		{
			name:      "returns refresh token",
			tokenHash: "refresh-token-hash",
			before: func(t *testing.T, userID uuid.UUID, tokenHash string) {
				t.Helper()
				if err := NewRefreshToken(testClient).Create(ctx, tokenHash, userID); err != nil {
					t.Fatalf("Create() setup error = %v", err)
				}
			},
		},
		{
			name:    "returns not found refresh token",
			wantErr: ErrRefreshTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRefreshTokens(t)
			userID := seedRefreshTokenUser(t)

			if tt.before != nil {
				tt.before(t, userID, tt.tokenHash)
			}

			got, err := NewRefreshToken(testClient).GetByTokenHash(ctx, tt.tokenHash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByTokenHash() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if got != nil {
					t.Errorf("GetByTokenHash() = %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("GetByTokenHash() = nil, want refresh token")
			}
			if got.UserID != userID {
				t.Errorf("GetByTokenHash() user ID = %v, want %v", got.UserID, userID)
			}
			if got.TokenHash != tt.tokenHash {
				t.Errorf("GetByTokenHash() token hash = %q, want %q", got.TokenHash, tt.tokenHash)
			}
			if got.RevokedAt != nil {
				t.Errorf("GetByTokenHash() revoked at = %v, want nil", got.RevokedAt)
			}
			if got.CreatedAt.IsZero() {
				t.Error("GetByTokenHash() created at is zero, want timestamp")
			}
		})
	}
}

func TestRefreshToken_RevokeByTokenHash(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		before  func(t *testing.T, userID uuid.UUID, tokenHash string)
		wantErr error
	}{
		{
			name: "revokes active refresh token",
			before: func(t *testing.T, userID uuid.UUID, tokenHash string) {
				t.Helper()
				if err := NewRefreshToken(testClient).Create(ctx, tokenHash, userID); err != nil {
					t.Fatalf("Create() setup error = %v", err)
				}
			},
		},
		{
			name:    "returns not found when the token hash does not exist",
			wantErr: ErrRefreshTokenNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetRefreshTokens(t)
			userID := seedRefreshTokenUser(t)
			tokenHash := uuid.NewString()

			if tt.before != nil {
				tt.before(t, userID, tokenHash)
			}

			err := NewRefreshToken(testClient).RevokeByTokenHash(ctx, tokenHash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("RevokeByTokenHash() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}

			got, err := testClient.Refresh_Token.Query().
				Where(refresh_token.TokenHashEQ(tokenHash)).
				Only(ctx)
			if err != nil {
				t.Fatalf("query refresh token: %v", err)
			}
			if got.RevokedAt == nil {
				t.Error("RevokeByTokenHash() revoked at is nil, want a timestamp")
			}
		})
	}
}
