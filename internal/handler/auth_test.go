package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/handler/mocks"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/security"
	"github.com/kcansari/mixo/internal/serializer"
	"github.com/stretchr/testify/assert"

	gomock "go.uber.org/mock/gomock"
)

func TestAuth_Logout(t *testing.T) {
	userID := uuid.New()
	frontendURL := "http://localhost:3000"
	errService := errors.New("service error")

	tests := []struct {
		name       string
		setup      func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc)
		wantStatus int
		wantCookie []*http.Cookie
		wantURL    string
		setCookie  bool
	}{
		{
			name: "success logout",
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().Logout(ctx, userID).Return(nil).Times(1)
			},
			wantStatus: http.StatusFound,
			wantCookie: []*http.Cookie{
				{
					Name:     string(security.TokenTypeAccess),
					Value:    "",
					Path:     "/",
					MaxAge:   middleware.DeleteCookieNow,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
				{
					Name:     string(security.TokenTypeRefresh),
					Value:    "",
					Path:     "/",
					MaxAge:   middleware.DeleteCookieNow,
					HttpOnly: true,
					Secure:   true,
					SameSite: http.SameSiteStrictMode,
				},
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
			ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, userID.String())

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

				if diff := cmp.Diff(tt.wantCookie, cookies, cmpopts.IgnoreFields(http.Cookie{}, "Raw", "RawExpires")); diff != "" {
					t.Errorf("cookies mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestAuth_Verify(t *testing.T) {
	tokens := domain.Tokens{
		AccessToken:  "acces-token",
		RefreshToken: "refresh-token",
	}

	tests := []struct {
		name         string
		setup        func(mockAuthSvc *mocks.MockAuthSvc)
		wantStatus   int
		modifyBody   func(*strings.Reader)
		wantResponse *serializer.GoogleVerifyResponse
	}{
		{
			name: "success verify",
			setup: func(mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().AuthenticateGoogle(gomock.Any(), gomock.Any()).Return(tokens, nil).Times(1)
			},
			wantStatus: http.StatusOK,
			wantResponse: &serializer.GoogleVerifyResponse{
				AccessToken:  tokens.AccessToken,
				RefreshToken: tokens.RefreshToken,
			},
		},
		{
			name: "service error",
			setup: func(mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().AuthenticateGoogle(gomock.Any(), gomock.Any()).Return(domain.Tokens{}, assert.AnError).Times(1)
			},
			wantStatus:   http.StatusInternalServerError,
			wantResponse: nil,
		},
		{
			name: "wrong body",
			modifyBody: func(body *strings.Reader) {
				*body = *strings.NewReader(`{"wrongField":"id-token"}`)
			},
			wantStatus:   http.StatusBadRequest,
			wantResponse: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAuthSvc := mocks.NewMockAuthSvc(ctrl)

			body := strings.NewReader(`{"idToken":"id-token"}`)
			if tt.modifyBody != nil {
				tt.modifyBody(body)
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/google/verify", body)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			if tt.setup != nil {
				tt.setup(mockAuthSvc)
			}

			auth := Auth{
				FrontendURL: "frontend-url",
				AuthSvc:     mockAuthSvc,
			}

			handler := NewAuth(auth)

			handler.Verify(w, req)

			resp := w.Result()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if tt.wantResponse != nil {
				var response serializer.GoogleVerifyResponse
				if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				if diff := cmp.Diff(tt.wantResponse, &response); diff != "" {
					t.Errorf("response mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
