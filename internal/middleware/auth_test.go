package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"
	gomock "go.uber.org/mock/gomock"

	"github.com/kcansari/mixo/internal/middleware/mocks"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/session"
)

func TestAuthMiddleware_RequireAuth(t *testing.T) {
	t.Parallel()

	userID := "user-id"

	tests := []struct {
		name           string
		accessToken    string
		setup          func(*mocks.MockSessionManager, *mocks.MockJWTSvc, *http.Request)
		wantStatus     int
		wantUserID     string
		wantNextCalled bool
	}{
		{
			name:           "valid request",
			accessToken:    "Bearer valid-token",
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
			setup: func(msm *mocks.MockSessionManager, mj *mocks.MockJWTSvc, req *http.Request) {
				mj.EXPECT().ExtractBearerToken(req).Return("valid-token", nil)

				msm.EXPECT().GetInfo("valid-token").Return(session.SessionInfo{
					CustomClaims: &security.CustomClaims{
						TokenType: security.TokenTypeAccess,
						RegisteredClaims: jwt.RegisteredClaims{
							Subject: userID,
						},
					},
				}, nil)
			},
		},
		{
			name:       "missing authorization header",
			wantStatus: http.StatusBadRequest,
			setup: func(_ *mocks.MockSessionManager, mj *mocks.MockJWTSvc, req *http.Request) {
				mj.EXPECT().ExtractBearerToken(req).Return("", request.ErrNoTokenInRequest)
			},
		},
		{
			name:        "invalid authorization scheme",
			accessToken: "Basic valid-token",
			wantStatus:  http.StatusBadRequest,
			setup: func(_ *mocks.MockSessionManager, mj *mocks.MockJWTSvc, req *http.Request) {
				mj.EXPECT().ExtractBearerToken(req).Return("", request.ErrNoTokenInRequest)
			},
		},
		{
			name:        "session info returns error",
			accessToken: "Bearer invalid-token",
			wantStatus:  http.StatusInternalServerError,
			setup: func(msm *mocks.MockSessionManager, mj *mocks.MockJWTSvc, req *http.Request) {
				mj.EXPECT().ExtractBearerToken(req).Return("invalid-token", nil)
				msm.EXPECT().GetInfo("invalid-token").Return(session.SessionInfo{}, errors.New("parse token"))
			},
		},
		{
			name:        "expired access token",
			accessToken: "Bearer expired-token",
			wantStatus:  http.StatusUnauthorized,
			setup: func(msm *mocks.MockSessionManager, mj *mocks.MockJWTSvc, req *http.Request) {
				mj.EXPECT().ExtractBearerToken(req).Return("expired-token", nil)
				msm.EXPECT().GetInfo("expired-token").Return(session.SessionInfo{
					IsExpired: true,
					CustomClaims: &security.CustomClaims{
						TokenType: security.TokenTypeAccess,
						RegisteredClaims: jwt.RegisteredClaims{
							Subject: userID,
						},
					},
				}, nil)
			},
		},
		{
			name:        "refresh token is rejected",
			accessToken: "Bearer refresh-token",
			wantStatus:  http.StatusUnauthorized,
			setup: func(msm *mocks.MockSessionManager, mj *mocks.MockJWTSvc, req *http.Request) {
				mj.EXPECT().ExtractBearerToken(req).Return("refresh-token", nil)
				msm.EXPECT().GetInfo("refresh-token").Return(session.SessionInfo{
					CustomClaims: &security.CustomClaims{
						TokenType: security.TokenTypeRefresh,
						RegisteredClaims: jwt.RegisteredClaims{
							Subject: userID,
						},
					},
				}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)

			sessionManager := mocks.NewMockSessionManager(ctrl)
			jwtSvc := mocks.NewMockJWTSvc(ctrl)

			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			req.Header.Set("Authorization", tt.accessToken)

			rr := httptest.NewRecorder()

			if tt.setup != nil {
				tt.setup(sessionManager, jwtSvc, req)
			}

			authMiddleware := NewAuth(sessionManager, jwtSvc)

			var capturedContext context.Context
			nextCalled := false

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				capturedContext = r.Context()
				w.WriteHeader(http.StatusOK)
			})

			authMiddleware.RequireAuth(testHandler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("RequireAuth() status = %d, want %d", rr.Code, tt.wantStatus)
			}

			if nextCalled != tt.wantNextCalled {
				t.Errorf("RequireAuth() nextCalled = %v, want %v", nextCalled, tt.wantNextCalled)
			}

			if tt.wantUserID != "" {
				if capturedContext == nil {
					t.Fatal("RequireAuth() context was not captured")
				}

				gotUserID, ok := UserIDFromContext(capturedContext)
				if !ok {
					t.Fatal("RequireAuth() did not add userID to context")
				}

				if gotUserID != tt.wantUserID {
					t.Errorf("RequireAuth() userID = %s, want %s", gotUserID, tt.wantUserID)
				}
			}
		})
	}
}
