package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/oauth"
	"github.com/kcansari/mixo/internal/services/mocks"
	"github.com/kcansari/mixo/internal/store"
	gomock "go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

func TestAuth_GetGoogleRedirectURL(t *testing.T) {
	errCache := errors.New("cache set failed")

	const (
		verifier    = "test-verifier"
		state       = "test-state"
		redirectURL = "https://example.com/oauth"
	)
	cacheKey := outhGoogleTag + state

	tests := []struct {
		name    string
		setup   func(*mocks.MockOAuthGoogle, *mocks.MockCache)
		wantURL string
		wantErr error
	}{
		{
			name:    "returns redirect URL after caching verifier",
			wantURL: redirectURL,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache) {
				oauthMock.EXPECT().
					GetRedirectURL().
					Return(verifier, state, redirectURL).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(outhGoogleTag, state).
					Return(cacheKey, nil).
					Times(1)

				cacheMock.EXPECT().
					Set(
						gomock.Any(),
						cacheKey,
						verifier,
						5*time.Minute,
					).
					Return(nil).
					Times(1)
			},
		},
		{
			name:    "returns error when caching verifier fails",
			wantURL: "",
			wantErr: errCache,
			setup: func(
				oauthMock *mocks.MockOAuthGoogle,
				cacheMock *mocks.MockCache,
			) {
				oauthMock.EXPECT().
					GetRedirectURL().
					Return(verifier, state, redirectURL).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(outhGoogleTag, state).
					Return(cacheKey, nil).
					Times(1)

				cacheMock.EXPECT().
					Set(
						gomock.Any(),
						cacheKey,
						verifier,
						5*time.Minute,
					).
					Return(errCache).
					Times(1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			ouathMock := mocks.NewMockOAuthGoogle(ctrl)
			cacheMock := mocks.NewMockCache(ctrl)

			tt.setup(ouathMock, cacheMock)

			auth := NewAuth(ouathMock, cacheMock, nil, nil, nil)

			gotURL, gotErr := auth.GetGoogleRedirectURL(context.Background())

			if gotErr != nil && !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("GetGoogleRedirectURL() error = %v, want %v", gotErr, tt.wantErr)
			}

			if gotURL != tt.wantURL {
				t.Errorf("GetGoogleRedirectURL() URL = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestAuth_AuthenticateGoogle(t *testing.T) {
	const (
		state          = "test-state"
		code           = "test-code"
		verifier       = "test-verifier"
		sessionHash    = "test-session-hash"
		encryptedToken = "encrypted-refresh-token"
		refreshToken   = "test-refresh-token"
	)

	errCacheGet := errors.New("cache get failed")
	errCacheDelete := errors.New("cache delete failed")
	errExchange := errors.New("exchange failed")
	errUserInfo := errors.New("get user info failed")
	errUserLookup := errors.New("user lookup failed")
	errEncrypt := errors.New("encrypt failed")
	errUserCreate := errors.New("user create failed")
	errSessionCache := errors.New("session cache failed")

	newUserID := uuid.New()
	existingUserID := uuid.New()
	token := &oauth2.Token{RefreshToken: refreshToken}
	verifierKey := outhGoogleTag + state
	sessionID := "test-session-id"

	user := oauth.GoogleUserInfo{
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "testName",
		GivenName:     "testGivenName",
		FamilyName:    "testFamilyName",
		Picture:       "testPicture",
		ID:            "test-id",
	}

	userCreate := domain.UserCreate{
		UserFields: domain.UserFields{
			Email:          user.Email,
			ProviderUserID: user.ID,
			EmailVerified:  user.EmailVerified,
			Name:           user.Name,
			GivenName:      user.GivenName,
			FamilyName:     user.FamilyName,
			Picture:        user.Picture,
		},
		RefreshToken: encryptedToken,
	}

	expectVerifier := func(cacheMock *mocks.MockCache) {

		cacheMock.EXPECT().
			KeyCreator(outhGoogleTag, state).
			Return(verifierKey, nil).
			Times(1)

		cacheMock.EXPECT().
			Get(gomock.Any(), verifierKey).
			Return(verifier, nil).
			Times(1)

		cacheMock.EXPECT().
			Delete(gomock.Any(), verifierKey).
			Return(nil).
			Times(1)
	}

	expectOAuth := func(oauthMock *mocks.MockOAuthGoogle) {
		oauthMock.EXPECT().
			Exchange(gomock.Any(), code, verifier).
			Return(token, nil).
			Times(1)

		oauthMock.EXPECT().
			GetUserInfo(gomock.Any(), token).
			Return(user, nil).
			Times(1)
	}

	tests := []struct {
		name        string
		wantSession bool
		wantErr     error
		setup       func(*mocks.MockOAuthGoogle, *mocks.MockCache, *mocks.MockAuthUserStore, *mocks.MockChiper, *mocks.MockSessionManager)
	}{
		{
			name:        "successfully authenticates a new user",
			wantSession: true,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, userStoreMock *mocks.MockAuthUserStore, chiperMock *mocks.MockChiper, sessionManagerMock *mocks.MockSessionManager) {
				expectVerifier(cacheMock)
				expectOAuth(oauthMock)

				userStoreMock.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).
					Return(nil, store.ErrUserNotFound).
					Times(1)

				chiperMock.EXPECT().
					Encrypt(refreshToken).
					Return(encryptedToken, nil).
					Times(1)

				userStoreMock.EXPECT().
					Create(gomock.Any(), userCreate).
					Return(&domain.User{ID: newUserID}, nil).
					Times(1)

				sessionManagerMock.EXPECT().
					Create(gomock.Any(), newUserID.String()).
					Return(sessionID, nil).
					Times(1)
			},
		},
		{
			name:        "successfully authenticates an existing user",
			wantSession: true,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, userStoreMock *mocks.MockAuthUserStore, _ *mocks.MockChiper, sessionManagerMock *mocks.MockSessionManager) {
				expectVerifier(cacheMock)
				expectOAuth(oauthMock)

				userStoreMock.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).
					Return(&domain.User{ID: existingUserID}, nil).
					Times(1)

				sessionManagerMock.EXPECT().
					Create(gomock.Any(), existingUserID.String()).
					Return(sessionID, nil).
					Times(1)
			},
		},
		{
			name:    "returns error when verifier lookup fails",
			wantErr: errCacheGet,
			setup: func(_ *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, _ *mocks.MockAuthUserStore, _ *mocks.MockChiper, _ *mocks.MockSessionManager) {
				cacheMock.EXPECT().
					KeyCreator(outhGoogleTag, state).
					Return(verifierKey, nil).
					Times(1)

				cacheMock.EXPECT().
					Get(gomock.Any(), verifierKey).
					Return("", errCacheGet).
					Times(1)
			},
		},
		{
			name:    "returns error when verifier deletion fails",
			wantErr: errCacheDelete,
			setup: func(_ *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, _ *mocks.MockAuthUserStore, _ *mocks.MockChiper, _ *mocks.MockSessionManager) {
				cacheMock.EXPECT().
					KeyCreator(outhGoogleTag, state).
					Return(verifierKey, nil).
					Times(1)

				cacheMock.EXPECT().
					Get(gomock.Any(), verifierKey).
					Return(verifier, nil).
					Times(1)

				cacheMock.EXPECT().
					Delete(gomock.Any(), verifierKey).
					Return(errCacheDelete).
					Times(1)
			},
		},
		{
			name:    "returns error when token exchange fails",
			wantErr: errExchange,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, _ *mocks.MockAuthUserStore, _ *mocks.MockChiper, _ *mocks.MockSessionManager) {
				expectVerifier(cacheMock)

				oauthMock.EXPECT().
					Exchange(gomock.Any(), code, verifier).
					Return(nil, errExchange).
					Times(1)
			},
		},
		{
			name:    "returns error when getting user info fails",
			wantErr: errUserInfo,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, _ *mocks.MockAuthUserStore, _ *mocks.MockChiper, _ *mocks.MockSessionManager) {
				expectVerifier(cacheMock)

				oauthMock.EXPECT().
					Exchange(gomock.Any(), code, verifier).
					Return(token, nil).
					Times(1)

				oauthMock.EXPECT().
					GetUserInfo(gomock.Any(), token).
					Return(oauth.GoogleUserInfo{}, errUserInfo).
					Times(1)
			},
		},
		{
			name:    "returns error when user lookup fails",
			wantErr: errUserLookup,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, userStoreMock *mocks.MockAuthUserStore, _ *mocks.MockChiper, _ *mocks.MockSessionManager) {
				expectVerifier(cacheMock)
				expectOAuth(oauthMock)

				userStoreMock.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).
					Return(nil, errUserLookup).
					Times(1)
			},
		},
		{
			name:    "returns error when refresh token encryption fails",
			wantErr: errEncrypt,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, userStoreMock *mocks.MockAuthUserStore, chiperMock *mocks.MockChiper, _ *mocks.MockSessionManager) {
				expectVerifier(cacheMock)
				expectOAuth(oauthMock)

				userStoreMock.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).
					Return(nil, store.ErrUserNotFound).
					Times(1)

				chiperMock.EXPECT().
					Encrypt(refreshToken).
					Return("", errEncrypt).
					Times(1)
			},
		},
		{
			name:    "returns error when creating new user fails",
			wantErr: errUserCreate,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, userStoreMock *mocks.MockAuthUserStore, chiperMock *mocks.MockChiper, _ *mocks.MockSessionManager) {
				expectVerifier(cacheMock)
				expectOAuth(oauthMock)

				userStoreMock.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).
					Return(nil, store.ErrUserNotFound).
					Times(1)

				chiperMock.EXPECT().
					Encrypt(refreshToken).
					Return(encryptedToken, nil).
					Times(1)

				userStoreMock.EXPECT().
					Create(gomock.Any(), userCreate).
					Return(nil, errUserCreate).
					Times(1)
			},
		},
		{
			name:    "returns error when caching session fails",
			wantErr: errSessionCache,
			setup: func(oauthMock *mocks.MockOAuthGoogle, cacheMock *mocks.MockCache, userStoreMock *mocks.MockAuthUserStore, _ *mocks.MockChiper, sessionManagerMock *mocks.MockSessionManager) {
				expectVerifier(cacheMock)
				expectOAuth(oauthMock)

				userStoreMock.EXPECT().
					GetByProviderUserID(gomock.Any(), user.ID).
					Return(&domain.User{ID: existingUserID}, nil).
					Times(1)

				sessionManagerMock.EXPECT().
					Create(gomock.Any(), existingUserID.String()).
					Return(sessionID, errSessionCache).
					Times(1)

			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			oauthMock := mocks.NewMockOAuthGoogle(ctrl)
			cacheMock := mocks.NewMockCache(ctrl)
			userStoreMock := mocks.NewMockAuthUserStore(ctrl)
			chiperMock := mocks.NewMockChiper(ctrl)
			sessionManagerMock := mocks.NewMockSessionManager(ctrl)

			tt.setup(oauthMock, cacheMock, userStoreMock, chiperMock, sessionManagerMock)

			auth := NewAuth(oauthMock, cacheMock, userStoreMock, chiperMock, sessionManagerMock)

			gotSessionID, gotErr := auth.AuthenticateGoogle(context.Background(), code, state)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("AuthenticateGoogle() error = %v, want %v", gotErr, tt.wantErr)
			}

			if tt.wantSession && gotSessionID == "" {
				t.Error("AuthenticateGoogle() session ID is empty, want a generated session ID")
			}
			if !tt.wantSession && gotSessionID != "" {
				t.Errorf("AuthenticateGoogle() session ID = %q, want empty", gotSessionID)
			}
		})
	}
}

func TestAuth_Logout(t *testing.T) {
	const (
		sessionID   = "test-session-id"
		sessionHash = "test-session-hash"
	)

	errCacheDelete := errors.New("cache delete failed")

	tests := []struct {
		name    string
		wantErr error
		setup   func(sessionManagerMock *mocks.MockSessionManager)
	}{
		{
			name: "successfully logs out",
			setup: func(sessionManagerMock *mocks.MockSessionManager) {
				sessionManagerMock.EXPECT().
					Destroy(gomock.Any(), sessionID).
					Return(nil).
					Times(1)
			},
		},
		{
			name: "returns error when deleting session fails",
			setup: func(sessionManagerMock *mocks.MockSessionManager) {
				sessionManagerMock.EXPECT().
					Destroy(gomock.Any(), sessionID).
					Return(errCacheDelete).
					Times(1)
			},
			wantErr: errCacheDelete,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			sessionManagerMock := mocks.NewMockSessionManager(ctrl)

			tt.setup(sessionManagerMock)

			auth := NewAuth(nil, nil, nil, nil, sessionManagerMock)

			gotErr := auth.Logout(context.Background(), sessionID)
			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("Logout() error = %v, want %v", gotErr, tt.wantErr)
			}
		})
	}
}
