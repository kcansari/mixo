package session

import (
	"context"
	"errors"
	"testing"
	time "time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/store"
	"go.uber.org/mock/gomock"
)

func TestSession_Create(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	errGenerateAccessToken := errors.New("generate access token")
	errGenerateRefreshToken := errors.New("generate refresh token")
	errStoreRefreshToken := errors.New("store refresh token")

	const (
		accessToken      = "access-token"
		refreshToken     = "refresh-token"
		refreshTokenHash = "refresh-token-hash"
	)

	tests := []struct {
		name    string
		setup   func(*MockJWTSvc, *MockHMACSvc, *MockTokenStore)
		want    domain.Tokens
		wantErr error
	}{
		{
			name: "creates tokens and stores hashed refresh token",
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					jwtSvc.EXPECT().
						GenerateJWT(userID, gomock.Any(), gomock.Any()).
						Return(accessToken, nil),
					jwtSvc.EXPECT().
						GenerateJWT(userID, gomock.Any(), gomock.Any()).
						Return(refreshToken, nil),
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),
					tokenStore.EXPECT().
						Create(gomock.Any(), refreshTokenHash, userID).
						Return(nil),
				)
			},
			want: domain.Tokens{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		{
			name: "returns error when access token generation fails",
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				jwtSvc.EXPECT().
					GenerateJWT(userID, gomock.Any(), gomock.Any()).
					Return("", errGenerateAccessToken)
			},
			wantErr: errGenerateAccessToken,
		},
		{
			name: "returns error when refresh token generation fails",
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					jwtSvc.EXPECT().
						GenerateJWT(userID, gomock.Any(), gomock.Any()).
						Return(accessToken, nil),
					jwtSvc.EXPECT().
						GenerateJWT(userID, gomock.Any(), gomock.Any()).
						Return("", errGenerateRefreshToken),
				)
			},
			wantErr: errGenerateRefreshToken,
		},
		{
			name: "returns error when storing refresh token fails",
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					jwtSvc.EXPECT().
						GenerateJWT(userID, gomock.Any(), gomock.Any()).
						Return(accessToken, nil),
					jwtSvc.EXPECT().
						GenerateJWT(userID, gomock.Any(), gomock.Any()).
						Return(refreshToken, nil),
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),
					tokenStore.EXPECT().
						Create(gomock.Any(), refreshTokenHash, userID).
						Return(errStoreRefreshToken),
				)
			},
			wantErr: errStoreRefreshToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			jwtSvc := NewMockJWTSvc(ctrl)
			hmacSvc := NewMockHMACSvc(ctrl)
			tokenStore := NewMockTokenStore(ctrl)

			tt.setup(jwtSvc, hmacSvc, tokenStore)

			session := NewSession(jwtSvc, hmacSvc, tokenStore)

			got, err := session.Create(ctx, userID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Create() error = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if got != tt.want {
				t.Errorf("Create() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSession_Destroy(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	errRevokeToken := errors.New("revoke token")

	const (
		accessToken      = "access-token"
		refreshToken     = "refresh-token"
		refreshTokenHash = "refresh-token-hash"
	)

	tests := []struct {
		name    string
		setup   func(*MockTokenStore)
		wantErr error
	}{
		{
			name:    "revoke the token",
			wantErr: nil,
			setup: func(tokenStore *MockTokenStore) {
				gomock.InOrder(
					tokenStore.EXPECT().
						Revoke(gomock.Any(), userID).
						Return(nil),
				)
			},
		},
		{
			name:    "error revoke token",
			wantErr: errRevokeToken,
			setup: func(tokenStore *MockTokenStore) {
				gomock.InOrder(
					tokenStore.EXPECT().
						Revoke(gomock.Any(), userID).
						Return(errRevokeToken),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			jwtSvc := NewMockJWTSvc(ctrl)
			hmacSvc := NewMockHMACSvc(ctrl)
			tokenStore := NewMockTokenStore(ctrl)

			tt.setup(tokenStore)

			session := NewSession(jwtSvc, hmacSvc, tokenStore)

			err := session.Destroy(ctx, userID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Destroy() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestSession_GetAccesToken(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	const (
		accessToken      = "access-token"
		refreshToken     = "refresh-token"
		refreshTokenHash = "refresh-token-hash"
	)

	var (
		ErrGetByTokenHash = errors.New("get by token hash")
		ErrGenJWT         = errors.New("gen jwt error")
	)

	token := &domain.RefreshToken{
		UserID:    userID,
		TokenHash: refreshTokenHash,
		RevokedAt: nil,
		CreatedAt: time.Now(),
	}

	tests := []struct {
		name    string
		setup   func(*MockJWTSvc, *MockHMACSvc, *MockTokenStore)
		want    string
		wantErr error
	}{
		{
			name:    "get access token",
			wantErr: nil,
			want:    accessToken,
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),

					tokenStore.EXPECT().
						GetByTokenHash(gomock.Any(), refreshTokenHash).
						Return(token, nil),
					jwtSvc.EXPECT().
						GenerateJWT(token.UserID, gomock.Any(), gomock.Any()).
						Return(accessToken, nil),
				)
			},
		},
		{
			name:    "err get by token hash",
			wantErr: ErrGetByTokenHash,
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),

					tokenStore.EXPECT().
						GetByTokenHash(gomock.Any(), refreshTokenHash).
						Return(nil, ErrGetByTokenHash),
				)
			},
		},
		{
			name:    "err generate jwt",
			wantErr: ErrGenJWT,
			setup: func(jwtSvc *MockJWTSvc, hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),

					tokenStore.EXPECT().
						GetByTokenHash(gomock.Any(), refreshTokenHash).
						Return(token, nil),

					jwtSvc.EXPECT().
						GenerateJWT(token.UserID, gomock.Any(), gomock.Any()).
						Return("", ErrGenJWT),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			jwtSvc := NewMockJWTSvc(ctrl)
			hmacSvc := NewMockHMACSvc(ctrl)
			tokenStore := NewMockTokenStore(ctrl)

			tt.setup(jwtSvc, hmacSvc, tokenStore)

			session := NewSession(jwtSvc, hmacSvc, tokenStore)

			token, err := session.GetAccessToken(ctx, refreshToken)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetAccesToken() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && token != tt.want {
				t.Fatalf("GetAccesToken() token = %v, want %v", token, tt.want)
			}
		})
	}
}

func TestSession_GetRefreshToken(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")

	const (
		refreshToken     = "refresh-token"
		refreshTokenHash = "refresh-token-hash"
	)

	token := &domain.RefreshToken{
		UserID:    userID,
		TokenHash: refreshTokenHash,
		RevokedAt: nil,
		CreatedAt: time.Now(),
	}

	tests := []struct {
		name    string
		setup   func(*MockTokenStore)
		want    *domain.RefreshToken
		wantErr error
	}{
		{
			name:    "get refresh token",
			wantErr: nil,
			want:    token,
			setup: func(tokenStore *MockTokenStore) {
				gomock.InOrder(
					tokenStore.EXPECT().
						GetByUserID(gomock.Any(), userID).
						Return(token, nil),
				)
			},
		},
		{
			name:    "refresh token not found",
			wantErr: store.ErrRefreshTokenNotFound,
			want:    nil,
			setup: func(tokenStore *MockTokenStore) {
				gomock.InOrder(
					tokenStore.EXPECT().
						GetByUserID(gomock.Any(), userID).
						Return(nil, store.ErrRefreshTokenNotFound),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			tokenStore := NewMockTokenStore(ctrl)

			tt.setup(tokenStore)

			session := NewSession(nil, nil, tokenStore)

			token, err := session.GetRefreshToken(ctx, userID)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetAccesToken() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && token != tt.want {
				t.Fatalf("GetAccesToken() token = %v, want %v", token, tt.want)
			}
		})
	}
}

func TestSession_GetInfo(t *testing.T) {

	const (
		accessToken = "access-token"
	)

	var (
		ErrParseJWT = errors.New("gen jwt error")
	)

	CustomClaims := &security.CustomClaims{
		TokenType: "token-type",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "issuer",
			Subject:   "subject",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	tests := []struct {
		name    string
		setup   func(*MockJWTSvc)
		want    SessionInfo
		wantErr error
	}{
		{
			name:    "get token info",
			wantErr: nil,
			want: SessionInfo{
				IsExpired:    false,
				CustomClaims: CustomClaims,
			},
			setup: func(jwtSvc *MockJWTSvc) {
				gomock.InOrder(
					jwtSvc.EXPECT().
						ParseJWT(gomock.Any()).
						Return(CustomClaims, nil),
				)
			},
		},
		{
			name:    "get expired token info",
			wantErr: nil,
			want: SessionInfo{
				IsExpired:    true,
				CustomClaims: CustomClaims,
			},
			setup: func(jwtSvc *MockJWTSvc) {
				gomock.InOrder(
					jwtSvc.EXPECT().
						ParseJWT(gomock.Any()).
						Return(CustomClaims, jwt.ErrTokenExpired),
				)
			},
		},
		{
			name:    "get invalid token info",
			wantErr: ErrParseJWT,
			setup: func(jwtSvc *MockJWTSvc) {
				gomock.InOrder(
					jwtSvc.EXPECT().
						ParseJWT(gomock.Any()).
						Return(nil, ErrParseJWT),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			jwtSvc := NewMockJWTSvc(ctrl)

			tt.setup(jwtSvc)

			session := NewSession(jwtSvc, nil, nil)

			info, err := session.GetInfo(accessToken)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetInfo() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil && info != tt.want {
				t.Fatalf("GetInfo() info = %v, want %v", info, tt.want)
			}
		})
	}
}

func TestSession_IsValidRefreshToken(t *testing.T) {

	const (
		refreshToken     = "refresh-token"
		refreshTokenHash = "refresh-token-hash"
	)

	token := &domain.RefreshToken{
		UserID:    uuid.New(),
		TokenHash: refreshTokenHash,
		RevokedAt: &time.Time{},
		CreatedAt: time.Now(),
	}

	tests := []struct {
		name    string
		setup   func(*MockHMACSvc, *MockTokenStore)
		want    bool
		wantErr error
	}{
		{
			name: "valid refresh token",
			want: true,
			setup: func(hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),
					tokenStore.EXPECT().
						GetByTokenHash(gomock.Any(), refreshTokenHash).
						Return(token, nil),
				)
			},
		},
		{
			name: "invalid refresh token",
			want: false,
			setup: func(hmacSvc *MockHMACSvc, tokenStore *MockTokenStore) {
				gomock.InOrder(
					hmacSvc.EXPECT().
						Sign(refreshToken).
						Return(refreshTokenHash),
					tokenStore.EXPECT().
						GetByTokenHash(gomock.Any(), refreshTokenHash).
						Return(nil, nil),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			hmacSvc := NewMockHMACSvc(ctrl)
			tokenStore := NewMockTokenStore(ctrl)

			tt.setup(hmacSvc, tokenStore)

			session := NewSession(nil, hmacSvc, tokenStore)

			isValid, err := session.IsValidRefreshToken(context.Background(), refreshToken)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("IsValidRefreshToken() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && isValid != tt.want {
				t.Fatalf("IsValidRefreshToken() isValid = %v, want %v", isValid, tt.want)
			}
		})
	}
}
