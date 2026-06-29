package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/oauth"
	"github.com/kcansari/mixo/internal/services/mocks"
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
