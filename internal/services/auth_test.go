package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/oauth"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/services/mocks"
	"github.com/kcansari/mixo/internal/session"
	"github.com/kcansari/mixo/internal/store"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
)

func TestAuth_AuthenticateGoogle(t *testing.T) {
	idToken := "id-token"
	user := &oauth.GoogleUserInfo{
		ID:            "24d2aeb3-ebf7-47ce-bdf3-7087c0488711",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "test-name",
		GivenName:     "test-given-name",
		FamilyName:    "test-family-name",
		Picture:       "test-picture",
	}
	accessToken := "access-token"
	refreshToken := "refresh-token"
	tests := []struct {
		name    string
		setup   func(*mocks.MockOAuthGoogle, *mocks.MockAuthUserStore, *mocks.MockSessionManager)
		want    domain.Tokens
		wantErr error
	}{
		{
			name: "success with existing user",
			setup: func(oauthGoogle *mocks.MockOAuthGoogle, userStore *mocks.MockAuthUserStore, sessionManager *mocks.MockSessionManager) {
				oauthGoogle.EXPECT().
					VerifyIDToken(gomock.Any(), idToken).Return(user, nil)

				userStore.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).Return(&domain.User{
					ID: uuid.MustParse(user.ID),
					UserFields: domain.UserFields{
						Email:          user.Email,
						ProviderUserID: user.ID,
						EmailVerified:  user.EmailVerified,
						Name:           user.Name,
						GivenName:      user.GivenName,
						FamilyName:     user.FamilyName,
						Picture:        user.Picture,
					},
				}, nil)

				sessionManager.EXPECT().Create(gomock.Any(), uuid.MustParse(user.ID)).Return(domain.Tokens{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
				}, nil)
			},
			want: domain.Tokens{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			wantErr: nil,
		},
		{
			name: "success with new user",
			setup: func(oauthGoogle *mocks.MockOAuthGoogle, userStore *mocks.MockAuthUserStore, sessionManager *mocks.MockSessionManager) {
				oauthGoogle.EXPECT().
					VerifyIDToken(gomock.Any(), idToken).Return(user, nil)

				userStore.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).Return(nil, store.ErrUserNotFound)

				userStore.EXPECT().
					Create(gomock.Any(), domain.UserCreate{
						UserFields: domain.UserFields{
							Email:          user.Email,
							ProviderUserID: user.ID,
							EmailVerified:  user.EmailVerified,
							Name:           user.Name,
							GivenName:      user.GivenName,
							FamilyName:     user.FamilyName,
							Picture:        user.Picture,
						},
					}).Return(&domain.User{
					ID: uuid.MustParse(user.ID),
					UserFields: domain.UserFields{
						Email:          user.Email,
						ProviderUserID: user.ID,
						EmailVerified:  user.EmailVerified,
						Name:           user.Name,
						GivenName:      user.GivenName,
						FamilyName:     user.FamilyName,
						Picture:        user.Picture,
					},
				}, nil)

				sessionManager.EXPECT().Create(gomock.Any(), uuid.MustParse(user.ID)).Return(domain.Tokens{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
				}, nil)
			},
			want: domain.Tokens{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			wantErr: nil,
		},
		{
			name: "verifyIDToken error",
			setup: func(oauthGoogle *mocks.MockOAuthGoogle, userStore *mocks.MockAuthUserStore, sessionManager *mocks.MockSessionManager) {
				oauthGoogle.EXPECT().
					VerifyIDToken(gomock.Any(), idToken).Return(nil, assert.AnError)
			},
			want:    domain.Tokens{},
			wantErr: assert.AnError,
		},
		{
			name: "sessionmanager error",
			setup: func(oauthGoogle *mocks.MockOAuthGoogle, userStore *mocks.MockAuthUserStore, sessionManager *mocks.MockSessionManager) {
				oauthGoogle.EXPECT().
					VerifyIDToken(gomock.Any(), idToken).Return(user, nil)

				userStore.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).Return(&domain.User{
					ID: uuid.MustParse(user.ID),
					UserFields: domain.UserFields{
						Email:          user.Email,
						ProviderUserID: user.ID,
						EmailVerified:  user.EmailVerified,
						Name:           user.Name,
						GivenName:      user.GivenName,
						FamilyName:     user.FamilyName,
						Picture:        user.Picture,
					},
				}, nil)

				sessionManager.EXPECT().Create(gomock.Any(), uuid.MustParse(user.ID)).Return(domain.Tokens{}, assert.AnError)
			},
			want:    domain.Tokens{},
			wantErr: assert.AnError,
		},
		{
			name: "get exist user error",
			setup: func(oauthGoogle *mocks.MockOAuthGoogle, userStore *mocks.MockAuthUserStore, sessionManager *mocks.MockSessionManager) {
				oauthGoogle.EXPECT().
					VerifyIDToken(gomock.Any(), idToken).Return(user, nil)

				userStore.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).Return(nil, assert.AnError)
			},
			want:    domain.Tokens{},
			wantErr: assert.AnError,
		},
		{
			name: "create user error",
			setup: func(oauthGoogle *mocks.MockOAuthGoogle, userStore *mocks.MockAuthUserStore, sessionManager *mocks.MockSessionManager) {
				oauthGoogle.EXPECT().
					VerifyIDToken(gomock.Any(), idToken).Return(user, nil)

				userStore.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).Return(nil, store.ErrUserNotFound)

				userStore.EXPECT().
					Create(gomock.Any(), gomock.Any()).Return(nil, assert.AnError)
			},
			want:    domain.Tokens{},
			wantErr: assert.AnError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			oauthGoogle := mocks.NewMockOAuthGoogle(ctrl)
			userStore := mocks.NewMockAuthUserStore(ctrl)
			sessionManager := mocks.NewMockSessionManager(ctrl)

			if tt.setup != nil {
				tt.setup(oauthGoogle, userStore, sessionManager)
			}
			a := NewAuth(oauthGoogle, userStore, sessionManager)
			got, gotErr := a.AuthenticateGoogle(context.Background(), idToken)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("AuthenticateGoogle() error = %v, wantErr %v", gotErr, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("AuthenticateGoogle() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAuth_GetNewTokens(t *testing.T) {
	sessionInfo := session.SessionInfo{
		IsExpired: false,
		CustomClaims: &security.CustomClaims{
			TokenType: security.TokenTypeRefresh,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    security.JWTIssuer,
				Subject:   "24d2aeb3-ebf7-47ce-bdf3-7087c0488711",
			},
		},
	}
	accessToken := "access-token"
	refreshToken := "refresh-token"
	tests := []struct {
		name    string
		setup   func(*mocks.MockSessionManager)
		want    domain.Tokens
		wantErr error
	}{
		{
			name: "success get tokens",
			want: domain.Tokens{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			wantErr: nil,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().GetInfo(refreshToken).Return(sessionInfo, nil)

				sessionManager.EXPECT().
					CheckIsRevokedRefreshToken(context.Background(), refreshToken).
					Return(false, nil)

				sessionManager.EXPECT().
					Create(context.Background(), uuid.MustParse(sessionInfo.Subject)).
					Return(domain.Tokens{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
					}, nil)

				sessionManager.EXPECT().
					RevokeRefreshToken(context.Background(), refreshToken).
					Return(nil)
			},
		},
		{
			name:    "fail get info",
			want:    domain.Tokens{},
			wantErr: assert.AnError,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().
					GetInfo(refreshToken).
					Return(session.SessionInfo{}, assert.AnError)
			},
		},
		{
			name:    "wrong token type",
			want:    domain.Tokens{},
			wantErr: ErrInvalidTokenType,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().
					GetInfo(refreshToken).
					Return(session.SessionInfo{
						CustomClaims: &security.CustomClaims{
							TokenType: security.TokenTypeAccess,
						},
					}, nil)
			},
		},
		{
			name:    "expired token",
			want:    domain.Tokens{},
			wantErr: ErrRefreshTokenExpired,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().
					GetInfo(refreshToken).
					Return(session.SessionInfo{
						CustomClaims: &security.CustomClaims{
							TokenType: security.TokenTypeRefresh,
							RegisteredClaims: jwt.RegisteredClaims{
								ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)),
								IssuedAt:  jwt.NewNumericDate(time.Now()),
								Issuer:    security.JWTIssuer,
								Subject:   "24d2aeb3-ebf7-47ce-bdf3-7087c0488711",
							},
						},
						IsExpired: true,
					}, nil)

				sessionManager.EXPECT().
					RevokeRefreshToken(gomock.Any(), refreshToken).
					Return(nil)
			},
		},
		{
			name:    "expired token revoke error",
			want:    domain.Tokens{},
			wantErr: assert.AnError,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().
					GetInfo(refreshToken).
					Return(session.SessionInfo{
						CustomClaims: &security.CustomClaims{
							TokenType: security.TokenTypeRefresh,
							RegisteredClaims: jwt.RegisteredClaims{
								Subject: "24d2aeb3-ebf7-47ce-bdf3-7087c0488711",
							},
						},
						IsExpired: true,
					}, nil)

				sessionManager.EXPECT().
					RevokeRefreshToken(gomock.Any(), refreshToken).
					Return(assert.AnError)
			},
		},
		{
			name:    "revoked token",
			want:    domain.Tokens{},
			wantErr: ErrRefreshTokenAlreadyUsed,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().GetInfo(refreshToken).Return(sessionInfo, nil)

				sessionManager.EXPECT().
					CheckIsRevokedRefreshToken(context.Background(), refreshToken).
					Return(true, nil)
			},
		},
		{
			name:    "create error",
			want:    domain.Tokens{},
			wantErr: assert.AnError,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().GetInfo(refreshToken).Return(sessionInfo, nil)

				sessionManager.EXPECT().
					CheckIsRevokedRefreshToken(context.Background(), refreshToken).
					Return(false, nil)

				sessionManager.EXPECT().
					Create(context.Background(), uuid.MustParse(sessionInfo.Subject)).
					Return(domain.Tokens{}, assert.AnError)
			},
		},
		{
			name:    "revoke refresh token error",
			want:    domain.Tokens{},
			wantErr: assert.AnError,
			setup: func(sessionManager *mocks.MockSessionManager) {
				sessionManager.EXPECT().GetInfo(refreshToken).Return(sessionInfo, nil)

				sessionManager.EXPECT().
					CheckIsRevokedRefreshToken(context.Background(), refreshToken).
					Return(false, nil)

				sessionManager.EXPECT().
					Create(context.Background(), uuid.MustParse(sessionInfo.Subject)).
					Return(domain.Tokens{
						AccessToken:  accessToken,
						RefreshToken: refreshToken,
					}, nil)

				sessionManager.EXPECT().
					RevokeRefreshToken(context.Background(), refreshToken).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			oauthGoogle := mocks.NewMockOAuthGoogle(ctrl)
			userStore := mocks.NewMockAuthUserStore(ctrl)
			sessionManager := mocks.NewMockSessionManager(ctrl)

			if tt.setup != nil {
				tt.setup(sessionManager)
			}
			a := NewAuth(oauthGoogle, userStore, sessionManager)
			got, gotErr := a.GetNewTokens(context.Background(), refreshToken)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("GetNewTokens() error = %v, wantErr %v", gotErr, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetNewTokens() diff (-want +got):\n%s", diff)
			}
		})
	}
}
