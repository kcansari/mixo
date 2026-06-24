package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
	"github.com/kcansari/mixo/internal/services/mocks"
	gomock "go.uber.org/mock/gomock"
)

func TestUser_GetByID(t *testing.T) {
	ErrUserNotFound := errors.New("user not found")
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
		setup        func(*mocks.MockUserStore)
		wantErr      error
		userID       string
		want         *domain.User
		wantAnyError bool
	}{
		{
			name: "get user succesfully",
			setup: func(mockUserStore *mocks.MockUserStore) {
				mockUserStore.EXPECT().GetByID(gomock.Any(), user.ID).Return(user, nil)
			},
			userID:       user.ID.String(),
			want:         user,
			wantAnyError: false,
		},
		{
			name: "get user failed",
			setup: func(mockUserStore *mocks.MockUserStore) {
				mockUserStore.EXPECT().GetByID(gomock.Any(), user.ID).Return(nil, ErrUserNotFound)
			},
			userID:       user.ID.String(),
			wantErr:      ErrUserNotFound,
			want:         nil,
			wantAnyError: false,
		},
		{
			name:         "get user with invalid uuid",
			userID:       "not-a-uuid",
			wantErr:      errors.New("invalid UUID format"),
			want:         nil,
			wantAnyError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockUserStore := mocks.NewMockUserStore(ctrl)

			if tt.setup != nil {
				tt.setup(mockUserStore)
			}

			userService := &User{
				UserStore: mockUserStore,
			}

			result, err := userService.GetByID(context.Background(), tt.userID)
			if tt.wantAnyError {
				if err == nil {
					t.Errorf("User.GetByID() error = nil, want error")
					return
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("User.GetByID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if result != tt.want {
				t.Errorf("User.GetByID() = %v, want %v", result, tt.want)
			}
		})
	}
}
