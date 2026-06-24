package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/handler/mocks"
	"github.com/kcansari/mixo/internal/middleware"
	"github.com/kcansari/mixo/internal/serializer"
	"github.com/kcansari/mixo/internal/store"
	gomock "go.uber.org/mock/gomock"
)

func TestUser_GetByID(t *testing.T) {
	user := &domain.User{
		ID: uuid.New(),
		UserFields: domain.UserFields{
			Email:          "test@mail.com",
			ProviderUserID: "test-provider-user-id",
			EmailVerified:  true,
			Name:           "test-user-name",
			GivenName:      "test-given-name",
			FamilyName:     "test-family-name",
			Picture:        "test-picture",
			IsAdmin:        true,
		},
	}

	tests := []struct {
		name         string
		setup        func(ctx context.Context, mockAuthSvc *mocks.MockUserSvc)
		wantStatus   int
		wantResponse *serializer.UserResponse
		ignoreCtx    bool
	}{
		{
			name: "success get user",
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockUserSvc) {
				mockAuthSvc.EXPECT().GetByID(ctx, user.ID.String()).Return(user, nil).Times(1)
			},
			wantStatus:   http.StatusOK,
			wantResponse: serializer.NewUserResponse(user),
		},
		{
			name: "user not found",
			setup: func(ctx context.Context, mockAuthSvc *mocks.MockUserSvc) {
				mockAuthSvc.EXPECT().GetByID(ctx, user.ID.String()).Return(nil, store.ErrUserNotFound).Times(1)
			},
			wantStatus:   http.StatusNotFound,
			wantResponse: nil,
		},
		{
			name:         "unauthorized request",
			wantStatus:   http.StatusUnauthorized,
			wantResponse: nil,
			ignoreCtx:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockUserSvc := mocks.NewMockUserSvc(ctrl)

			req := httptest.NewRequest(http.MethodGet, "/user/me", nil)

			w := httptest.NewRecorder()
			ctx := context.WithValue(req.Context(), middleware.ContextKeyUserID, user.ID.String())

			if tt.setup != nil {
				tt.setup(ctx, mockUserSvc)
			}

			user := User{
				UserSvc: mockUserSvc,
			}

			handler := NewUser(user)

			if !tt.ignoreCtx {
				handler.GetByID(w, req.WithContext(ctx))
			} else {
				handler.GetByID(w, req)
			}

			resp := w.Result()

			if resp.StatusCode != tt.wantStatus {
				t.Fatalf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			if tt.wantResponse != nil {
				var response serializer.UserResponse
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
