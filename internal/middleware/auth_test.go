package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gomock "go.uber.org/mock/gomock"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/middleware/mocks"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/session"
	"github.com/kcansari/mixo/internal/store"
)

func TestAuthMiddleware_RequireAuth(t *testing.T) {
	var (
		errLogout          = errors.New("logouterr")
		errIsInvalid       = errors.New("isInvalid err")
		errCreateSession   = errors.New("create session err")
		errGetAccestoken   = errors.New("get acces token err")
		errGetRefreshtoken = errors.New("get refresh token err")
	)
	userID := uuid.New().String()
	accessToken := "test-access-token"
	newAccesstoken := "new-access-token"
	refreshToken := "test-refresh-token"
	newRefreshToken := "new-refresh-token"

	revokedAt := time.Now().Add(-20 * time.Second)

	recentlyRevokedRefreshToken := &domain.RefreshToken{
		UserID:    uuid.MustParse(userID),
		TokenHash: "test-token-hash",
		RevokedAt: &revokedAt,
		CreatedAt: time.Now(),
	}

	newTokens := domain.Tokens{
		AccessToken:  newAccesstoken,
		RefreshToken: newRefreshToken,
	}

	tests := []struct {
		name           string
		setup          func(*mocks.MockSessionManager)
		cookie         []*http.Cookie
		wantStatus     int
		wantUserID     string
		wantNextCalled bool
		wantCookies    []*http.Cookie
	}{
		{
			name: "authorized request",
			setup: func(msm *mocks.MockSessionManager) {

				msm.EXPECT().
					GetInfo(accessToken).
					Return(session.SessionInfo{
						IsExpired: false,
						CustomClaims: &security.CustomClaims{
							TokenType: security.TokenTypeAccess,
							RegisteredClaims: jwt.RegisteredClaims{
								Issuer:    security.JWTIssuer,
								Subject:   userID,
								IssuedAt:  jwt.NewNumericDate(time.Now()),
								ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
							},
						},
					}, nil)
			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
		},
		{
			name: "missing access token on cookie",
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name: "missing refresh token on cookie",
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
			},
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name:           "missing cookie",
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name: "invalid access token type",
			setup: func(msm *mocks.MockSessionManager) {
				msm.EXPECT().
					GetInfo(accessToken).
					Return(session.SessionInfo{
						IsExpired: false,
						CustomClaims: &security.CustomClaims{
							TokenType: security.TokenTypeRefresh,
							RegisteredClaims: jwt.RegisteredClaims{
								Issuer:    security.JWTIssuer,
								Subject:   userID,
								IssuedAt:  jwt.NewNumericDate(time.Now()),
								ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
							},
						},
					}, nil)
			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name: "invalid refresh token type",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
				)
			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
		},
		{
			name: "expired access token with not expired refresh token",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						GetAccessToken(gomock.Any(), refreshToken).
						Return(newAccesstoken, nil),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
			wantCookies: []*http.Cookie{
				{
					Name:     string(security.TokenTypeAccess),
					Value:    newAccesstoken,
					Path:     "/",
					MaxAge:   int(domain.DefaultAccessTokenExpiration.Seconds()),
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
			},
		},
		{
			name: "expired access token with expired refresh token and success logout",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(nil),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusFound,
			wantUserID:     "",
			wantNextCalled: false,
			wantCookies: []*http.Cookie{
				{
					Name:     string(security.TokenTypeAccess),
					Value:    "",
					Path:     "/",
					MaxAge:   DeleteCookieNow,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
				{
					Name:     string(security.TokenTypeRefresh),
					Value:    "",
					Path:     "/",
					MaxAge:   DeleteCookieNow,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
			},
		},
		{
			name: "expired access token with expired refresh token and failed logout",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(errLogout),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "expired access token with invalid refresh token succes invalid",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(false, nil),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusUnauthorized,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "expired access token with invalid refresh token failed invalid",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(false, errIsInvalid),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "expired access token with expire soon refresh token succes",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(nil),
					msm.EXPECT().
						Create(gomock.Any(), uuid.MustParse(userID)).
						Return(newTokens, nil),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
			wantCookies: []*http.Cookie{
				{
					Name:     string(security.TokenTypeAccess),
					Value:    newAccesstoken,
					Path:     "/",
					MaxAge:   int(domain.DefaultAccessTokenExpiration.Seconds()),
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
				{
					Name:     string(security.TokenTypeRefresh),
					Value:    newRefreshToken,
					Path:     "/",
					MaxAge:   int(domain.DefaultRefreshTokenExpiration.Seconds()),
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
			},
		},
		{
			name: "expired access token with expire soon refresh token destroy fails",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(errLogout),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "expired access token with expire soon refresh token destroy not found and token revoked recently",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(store.ErrRefreshTokenNotFound),
					msm.EXPECT().
						GetRefreshToken(gomock.Any(), uuid.MustParse(userID)).
						Return(recentlyRevokedRefreshToken, nil),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
		},
		{
			name: "expired access token with expire soon refresh token destroy not found and token revoked recently failed get refresh token info",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(store.ErrRefreshTokenNotFound),
					msm.EXPECT().
						GetRefreshToken(gomock.Any(), uuid.MustParse(userID)).
						Return(nil, errGetRefreshtoken),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "expired access token with expire soon refresh token create fails",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						Destroy(gomock.Any(), uuid.MustParse(userID)).
						Return(nil),
					msm.EXPECT().
						Create(gomock.Any(), uuid.MustParse(userID)).
						Return(domain.Tokens{}, errCreateSession),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "expired access token with not expire soon refresh token",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						GetAccessToken(gomock.Any(), refreshToken).
						Return(newAccesstoken, nil),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
			wantCookies: []*http.Cookie{
				{
					Name:     string(security.TokenTypeAccess),
					Value:    newAccesstoken,
					Path:     "/",
					MaxAge:   int(domain.DefaultAccessTokenExpiration.Seconds()),
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
			},
		},
		{
			name: "expired access token with not expire soon refresh token failed",
			setup: func(msm *mocks.MockSessionManager) {
				gomock.InOrder(
					msm.EXPECT().
						GetInfo(accessToken).
						Return(session.SessionInfo{
							IsExpired: true,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeAccess,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultAccessTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						GetInfo(refreshToken).
						Return(session.SessionInfo{
							IsExpired: false,
							CustomClaims: &security.CustomClaims{
								TokenType: security.TokenTypeRefresh,
								RegisteredClaims: jwt.RegisteredClaims{
									Issuer:    security.JWTIssuer,
									Subject:   userID,
									IssuedAt:  jwt.NewNumericDate(time.Now()),
									ExpiresAt: jwt.NewNumericDate(time.Now().Add(domain.DefaultRefreshTokenExpiration)),
								},
							},
						}, nil),
					msm.EXPECT().
						IsValidRefreshToken(gomock.Any(), refreshToken).
						Return(true, nil),
					msm.EXPECT().
						GetAccessToken(gomock.Any(), refreshToken).
						Return("", errGetAccestoken),
				)

			},
			cookie: []*http.Cookie{
				{
					Name:  string(security.TokenTypeAccess),
					Value: accessToken,
				},
				{
					Name:  string(security.TokenTypeRefresh),
					Value: refreshToken,
				},
			},
			wantStatus:     http.StatusInternalServerError,
			wantUserID:     "",
			wantNextCalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			sessionManager := mocks.NewMockSessionManager(ctrl)

			if tt.setup != nil {
				tt.setup(sessionManager)
			}

			authMiddleware := &AuthMiddleware{
				SessionManager: sessionManager,
			}

			var capturedContext context.Context
			nextCalled := false

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				capturedContext = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			if tt.cookie != nil {
				for _, cookie := range tt.cookie {
					req.AddCookie(cookie)
				}
			}

			rr := httptest.NewRecorder()

			authMiddleware.RequireAuth(testHandler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			if nextCalled != tt.wantNextCalled {
				t.Errorf("expected nextCalled %v, got %v", tt.wantNextCalled, nextCalled)
			}

			if len(tt.wantCookies) > 0 {
				diff := cmp.Diff(
					rr.Result().Cookies(),
					tt.wantCookies,
					cmpopts.IgnoreFields(http.Cookie{}, "Expires", "Raw"),
					cmpopts.SortSlices(func(a, b *http.Cookie) bool {
						return a.Name < b.Name
					}),
				)
				if diff != "" {
					t.Errorf("cookies mismatch (-got +want):\n%s", diff)
				}
			}

			if tt.wantUserID != "" {
				if capturedContext == nil {
					t.Fatal("expected context to be captured")
				}

				gotUserID, ok := UserIDFromContext(capturedContext)
				if !ok {
					t.Fatal("expected userID in context")
				}

				if gotUserID != tt.wantUserID {
					t.Errorf("expected userID %s, got %s", tt.wantUserID, gotUserID)
				}
			}
		})
	}
}
