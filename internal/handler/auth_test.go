package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/handler/mocks"
	"github.com/kcansari/mixo/internal/middleware"

	gomock "go.uber.org/mock/gomock"
)

func TestAuth_Google(t *testing.T) {
	redirectURL := "http://localhost:3359"
	tests := []struct {
		name       string
		setup      func(mockAuthSvc *mocks.MockAuthSvc)
		wantStatus int
		wantURL    string
	}{
		{
			name: "succes return",
			setup: func(mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().GetGoogleRedirectURL(gomock.Any()).Return(redirectURL, nil).Times(1)
			},
			wantStatus: http.StatusFound,
			wantURL:    redirectURL,
		},
		{
			name: "return any error",
			setup: func(MockAuthSvc *mocks.MockAuthSvc) {
				MockAuthSvc.EXPECT().GetGoogleRedirectURL(gomock.Any()).Return("", errors.New("any service error")).Times(1)
			},
			wantStatus: http.StatusInternalServerError,
			wantURL:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAuthSvc := mocks.NewMockAuthSvc(ctrl)

			tt.setup(mockAuthSvc)

			auth := Auth{
				FrontendURL: "http://localhost:3000",
				AuthSvc:     mockAuthSvc,
			}

			handler := NewAuth(auth)

			req := httptest.NewRequest(http.MethodGet, "/auth/google", nil)
			w := httptest.NewRecorder()
			handler.Google(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			location, _ := resp.Location()

			if strings.TrimSpace(tt.wantURL) != "" && location.String() != tt.wantURL {
				t.Errorf("expected location %s, got %s", tt.wantURL, location.String())
			}

		})
	}
}

func TestAuth_GoogleCallback(t *testing.T) {
	tokens := domain.Tokens{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}
	frontendURL := "http://localhost:3000"
	tests := []struct {
		name       string // description of this test case
		setup      func(mockAuthSvc *mocks.MockAuthSvc)
		wantStatus int
		wantCookie []*http.Cookie
		wantURL    string
		requestURL string
	}{
		{
			name: "success",
			setup: func(mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().AuthenticateGoogle(gomock.Any(), gomock.Any(), gomock.Any()).Return(tokens, nil).Times(1)
			},
			wantStatus: http.StatusFound,
			wantCookie: []*http.Cookie{
				{
					Name:     "refresh_token",
					Value:    tokens.RefreshToken,
					Path:     "/",
					MaxAge:   int(domain.DefaultRefreshTokenExpiration / time.Second),
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
				{
					Name:     "access_token",
					Value:    tokens.AccessToken,
					Path:     "/",
					MaxAge:   int(domain.DefaultAccessTokenExpiration / time.Second),
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
			},
			wantURL:    frontendURL,
			requestURL: "/auth/google/callback?code=test-code&state=test-state",
		},
		{
			name:       "access denied",
			wantStatus: http.StatusFound,
			wantURL:    frontendURL,
			requestURL: "/auth/google/callback?error=access_denied&state=test-state",
		},
		{
			name:       "missing query param code",
			wantStatus: http.StatusBadRequest,
			requestURL: "/auth/google/callback?state=test-state",
		},
		{
			name:       "missing query param state",
			wantStatus: http.StatusBadRequest,
			requestURL: "/auth/google/callback?code=test-code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAuthSvc := mocks.NewMockAuthSvc(ctrl)

			if tt.setup != nil {
				tt.setup(mockAuthSvc)
			}

			auth := Auth{
				FrontendURL: frontendURL,
				AuthSvc:     mockAuthSvc,
			}

			handler := NewAuth(auth)

			req := httptest.NewRequest(http.MethodGet, tt.requestURL, nil)
			w := httptest.NewRecorder()
			handler.GoogleCallback(w, req)

			resp := w.Result()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if tt.wantCookie != nil {
				cookies := resp.Cookies()

				if diff := cmp.Diff(tt.wantCookie, cookies, cmpopts.IgnoreFields(http.Cookie{}, "Raw")); diff != "" {
					t.Errorf("cookies mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestAuth_Logout(t *testing.T) {
	userID := "user-id"
	frontendURL := "http://localhost:3000"
	errService := errors.New("service error")

	tests := []struct {
		name       string
		setup      func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc)
		wantStatus int
		wantCookie *http.Cookie
		wantURL    string
		setCookie  bool
	}{
		{
			name: "success logout",
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().Logout(ctx, userID).Return(nil).Times(1)
			},
			wantStatus: http.StatusFound,
			wantCookie: &http.Cookie{
				Name:     "sid",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
			},
			wantURL:   frontendURL,
			setCookie: true,
		},
		{
			name: "error from service",
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().Logout(ctx, userID).Return(errService).Times(1)
			},
			wantStatus: http.StatusInternalServerError,
			setCookie:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAuthSvc := mocks.NewMockAuthSvc(ctrl)

			req := httptest.NewRequest(http.MethodPost, "/auth/google/logout", nil)

			w := httptest.NewRecorder()
			ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, userID)

			if tt.setup != nil {
				tt.setup(ctx, mockAuthSvc)
			}

			auth := Auth{
				FrontendURL: frontendURL,
				AuthSvc:     mockAuthSvc,
			}

			handler := NewAuth(auth)

			handler.Logout(w, req.WithContext(ctx))

			resp := w.Result()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if tt.wantCookie != nil {
				cookies := resp.Cookies()

				if diff := cmp.Diff([]*http.Cookie{tt.wantCookie}, cookies, cmpopts.IgnoreFields(http.Cookie{}, "Raw", "RawExpires")); diff != "" {
					t.Errorf("cookies mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
