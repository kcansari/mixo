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
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/handler/mocks"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/serializer"
	"github.com/stretchr/testify/assert"

	gomock "go.uber.org/mock/gomock"
)

func TestAuth_Logout(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	errService := errors.New("service error")

	tests := []struct {
		name          string
		addUserID     bool
		contextUserID string
		setup         func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc)
		wantStatus    int
	}{
		{
			name:          "mobile client receives no content after logout",
			addUserID:     true,
			contextUserID: userID.String(),
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().Logout(ctx, userID).Return(nil).Times(1)
			},
			wantStatus: http.StatusNoContent,
		},
		{
			name:          "error from service",
			addUserID:     true,
			contextUserID: userID.String(),
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockAuthSvc) {
				mockAuthSvc.EXPECT().Logout(ctx, userID).Return(errService).Times(1)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "missing user id in context",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:          "invalid user id in context",
			addUserID:     true,
			contextUserID: "invalid-user-id",
			wantStatus:    http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			mockAuthSvc := mocks.NewMockAuthSvc(ctrl)

			req := httptest.NewRequest(http.MethodPost, "/auth/google/logout", nil)

			w := httptest.NewRecorder()
			ctx := req.Context()
			if tt.addUserID {
				ctx = context.WithValue(ctx, middleware.ContextKeyUserID, tt.contextUserID)
			}

			if tt.setup != nil {
				tt.setup(ctx, mockAuthSvc)
			}

			auth := Auth{
				AuthSvc: mockAuthSvc,
			}

			handler := NewAuth(auth)

			handler.Logout(w, req.WithContext(ctx))

			resp := w.Result()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
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
				AuthSvc: mockAuthSvc,
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

func TestAuth_Refresh(t *testing.T) {
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
				mockAuthSvc.EXPECT().GetNewTokens(gomock.Any(), gomock.Any()).Return(tokens, nil).Times(1)
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
				mockAuthSvc.EXPECT().GetNewTokens(gomock.Any(), gomock.Any()).Return(domain.Tokens{}, assert.AnError).Times(1)
			},
			wantStatus:   http.StatusInternalServerError,
			wantResponse: nil,
		},
		{
			name: "wrong body",
			modifyBody: func(body *strings.Reader) {
				*body = *strings.NewReader(`{"wrongField":"refresh-token"}`)
			},
			wantStatus:   http.StatusBadRequest,
			wantResponse: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockAuthSvc := mocks.NewMockAuthSvc(ctrl)

			body := strings.NewReader(`{"refresh_token":"refresh-token"}`)
			if tt.modifyBody != nil {
				tt.modifyBody(body)
			}
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", body)
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()

			if tt.setup != nil {
				tt.setup(mockAuthSvc)
			}

			auth := Auth{
				AuthSvc: mockAuthSvc,
			}

			handler := NewAuth(auth)

			handler.Refresh(w, req)

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
