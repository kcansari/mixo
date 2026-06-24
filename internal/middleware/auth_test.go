package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	gomock "go.uber.org/mock/gomock"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/middleware/mocks"
)

func TestAuthMiddleware_RequireAuth(t *testing.T) {
	sid := "test-sid"
	userID := "user123"

	tests := []struct {
		name           string
		setup          func(*mocks.MockSessionManager)
		cookie         *http.Cookie
		wantStatus     int
		wantUserID     string
		wantNextCalled bool
	}{
		{
			name: "authorized request",
			setup: func(mm *mocks.MockSessionManager) {
				mm.EXPECT().Get(gomock.Any(), sid).Return(userID, nil)
				mm.EXPECT().ShouldExtend(gomock.Any(), sid).Return(false, nil)
			},
			cookie: &http.Cookie{
				Name:  "sid",
				Value: sid,
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
		},
		{

			name:           "missing cookie",
			setup:          nil,
			cookie:         nil,
			wantStatus:     http.StatusUnauthorized,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "invalid session",
			setup: func(mm *mocks.MockSessionManager) {
				mm.EXPECT().Get(gomock.Any(), sid).Return("", errors.New("session not found"))
			},
			cookie: &http.Cookie{
				Name:  "sid",
				Value: sid,
			},
			wantStatus:     http.StatusUnauthorized,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "should extend session",
			setup: func(mm *mocks.MockSessionManager) {
				mm.EXPECT().Get(gomock.Any(), sid).Return(userID, nil)
				mm.EXPECT().ShouldExtend(gomock.Any(), sid).Return(true, nil)
				mm.EXPECT().Extend(gomock.Any(), sid).Return(nil)
			},
			cookie: &http.Cookie{
				Name:  "sid",
				Value: sid,
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userID,
			wantNextCalled: true,
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
				req.AddCookie(tt.cookie)
			}

			rr := httptest.NewRecorder()

			authMiddleware.RequireAuth(testHandler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			if nextCalled != tt.wantNextCalled {
				t.Errorf("expected nextCalled %v, got %v", tt.wantNextCalled, nextCalled)
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

func TestAuthMiddleware_RequireAdmin(t *testing.T) {
	sid := "test-sid"
	userID := uuid.New()
	userIDStr := userID.String()

	tests := []struct {
		name           string
		setup          func(*mocks.MockSessionManager, *mocks.MockUserSvc)
		cookie         *http.Cookie
		wantStatus     int
		wantUserID     string
		wantNextCalled bool
	}{
		{
			name: "authorized request",
			setup: func(mm *mocks.MockSessionManager, um *mocks.MockUserSvc) {
				mm.EXPECT().Get(gomock.Any(), sid).Return(userIDStr, nil)
				um.EXPECT().GetByID(gomock.Any(), userIDStr).Return(&domain.User{ID: userID, UserFields: domain.UserFields{IsAdmin: true}}, nil)
			},
			cookie: &http.Cookie{
				Name:  "sid",
				Value: sid,
			},
			wantStatus:     http.StatusOK,
			wantUserID:     userIDStr,
			wantNextCalled: true,
		},
		{
			name: "not admin request",
			setup: func(mm *mocks.MockSessionManager, um *mocks.MockUserSvc) {
				mm.EXPECT().Get(gomock.Any(), sid).Return(userIDStr, nil)
				um.EXPECT().GetByID(gomock.Any(), userIDStr).Return(&domain.User{ID: userID, UserFields: domain.UserFields{IsAdmin: false}}, nil)
			},
			cookie: &http.Cookie{
				Name:  "sid",
				Value: sid,
			},
			wantStatus:     http.StatusForbidden,
			wantUserID:     userIDStr,
			wantNextCalled: false,
		},
		{

			name:           "missing cookie",
			setup:          nil,
			cookie:         nil,
			wantStatus:     http.StatusUnauthorized,
			wantUserID:     "",
			wantNextCalled: false,
		},
		{
			name: "invalid session",
			setup: func(mm *mocks.MockSessionManager, _ *mocks.MockUserSvc) {
				mm.EXPECT().Get(gomock.Any(), sid).Return("", errors.New("session not found"))
			},
			cookie: &http.Cookie{
				Name:  "sid",
				Value: sid,
			},
			wantStatus:     http.StatusUnauthorized,
			wantUserID:     "",
			wantNextCalled: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			sessionManager := mocks.NewMockSessionManager(ctrl)
			userSvc := mocks.NewMockUserSvc(ctrl)

			if tt.setup != nil {
				tt.setup(sessionManager, userSvc)
			}

			authMiddleware := &AuthMiddleware{
				SessionManager: sessionManager,
				UserSvc:        userSvc,
			}

			nextCalled := false

			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)

			if tt.cookie != nil {
				req.AddCookie(tt.cookie)
			}

			rr := httptest.NewRecorder()

			authMiddleware.RequireAdmin(testHandler).ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, rr.Code)
			}

			if nextCalled != tt.wantNextCalled {
				t.Errorf("expected nextCalled %v, got %v", tt.wantNextCalled, nextCalled)
			}

		})
	}
}
