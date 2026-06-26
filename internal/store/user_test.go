package store

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/kcansari/mixo/internal/domain"
)

// seedUser inserts a user through the store and returns its generated ID. It is
// a test helper, so it fails the test (rather than returning an error) on any
// problem.
func seedUser(t *testing.T, s *Users, user domain.UserCreate) uuid.UUID {
	t.Helper()
	res, err := s.Create(context.Background(), user)
	if err != nil {
		t.Fatalf("seedUser(): %v", err)
	}
	return res.ID
}

func TestUsers_Create(t *testing.T) {
	store := NewUsers(testClient)
	ctx := context.Background()
	providerID := uuid.NewString()

	user := domain.UserCreate{
		UserFields: domain.UserFields{
			Email:          "testuser@example.com",
			EmailVerified:  true,
			ProviderUserID: providerID,
			Name:           "test user name",
			GivenName:      "test given name",
			FamilyName:     "test family name",
			Picture:        "test-user-picture",
		},
		RefreshToken: "test-refresh-token",
	}

	tests := []struct {
		name          string
		user          domain.User
		before        func(t *testing.T)
		cancelContext bool
		wantErr       error
	}{
		{
			name: "saves a new user and returns the new user",
			user: domain.User{
				UserFields: domain.UserFields{
					Email:          "testuser@example.com",
					EmailVerified:  true,
					ProviderUserID: providerID,
					Name:           "test user name",
					GivenName:      "test given name",
					FamilyName:     "test family name",
					Picture:        "test-user-picture",
					IsAdmin:        false,
				},
			},
			wantErr: nil,
		},
		{
			name: "returns an error when the user already exists",
			user: domain.User{
				UserFields: domain.UserFields{
					Email:          "testuser@example.com",
					EmailVerified:  true,
					ProviderUserID: providerID,
					Name:           "test user name",
					GivenName:      "test given name",
					FamilyName:     "test family name",
					Picture:        "test-user-picture",
					IsAdmin:        false,
				},
			},
			before: func(t *testing.T) {
				seedUser(t, store, user)
			},
			wantErr: ErrUserAlreadyExists,
		},
		{
			name:          "returns an error when context is canceled",
			cancelContext: true,
			wantErr:       context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetUsers(t)

			if tt.before != nil {
				tt.before(t)
			}

			testCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			usr, err := store.Create(testCtx, user)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Create() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr != nil {
				if usr != nil {
					t.Errorf("Create() returned user %v, want nil", usr)
				}
				return
			}

			if usr == nil {
				t.Fatal("Create() returned nil, want a user")
			}

			got := domain.User{
				UserFields: domain.UserFields{
					Email:          usr.Email,
					EmailVerified:  usr.EmailVerified,
					ProviderUserID: usr.ProviderUserID,
					Name:           usr.Name,
					GivenName:      usr.GivenName,
					FamilyName:     usr.FamilyName,
					Picture:        usr.Picture,
					IsAdmin:        usr.IsAdmin,
				},
			}

			if diff := cmp.Diff(tt.user, got); diff != "" {
				t.Errorf("Create() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUsers_GetByProviderUserID(t *testing.T) {
	ctx := context.Background()
	providerID := uuid.NewString()
	userMock := domain.UserCreate{
		UserFields: domain.UserFields{
			Email:          "testuser@example.com",
			EmailVerified:  true,
			ProviderUserID: providerID,
			Name:           "test user name",
			GivenName:      "test given name",
			FamilyName:     "test family name",
			Picture:        "test-user-picture",
			IsAdmin:        false,
		},
		RefreshToken: "test-refresh-token",
	}

	tests := []struct {
		name          string
		user          domain.User
		before        func(t *testing.T) uuid.UUID
		cancelContext bool
		wantErr       error
	}{
		{
			name: "get user",
			user: domain.User{
				UserFields: domain.UserFields{
					Email:          "testuser@example.com",
					EmailVerified:  true,
					ProviderUserID: providerID,
					Name:           "test user name",
					GivenName:      "test given name",
					FamilyName:     "test family name",
					Picture:        "test-user-picture",
					IsAdmin:        false,
				},
			},
			before: func(t *testing.T) uuid.UUID {
				return seedUser(t, NewUsers(testClient), userMock)
			},
			wantErr: nil,
		},
		{
			name: "user not found",
			user: domain.User{
				UserFields: domain.UserFields{
					Email:          "testuser@example.com",
					EmailVerified:  true,
					ProviderUserID: providerID,
					Name:           "test user name",
					GivenName:      "test given name",
					FamilyName:     "test family name",
					Picture:        "test-user-picture",
					IsAdmin:        false,
				},
			},
			wantErr: ErrUserNotFound,
		},
		{
			name:          "returns an error when context is canceled",
			cancelContext: true,
			wantErr:       context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetUsers(t)

			if tt.before != nil {
				id := tt.before(t)
				tt.user.ID = id
			}

			testCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			usr, err := NewUsers(testClient).GetByProviderUserID(testCtx, providerID)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByProviderUserID() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr == nil {
				got := domain.User{
					UserFields: domain.UserFields{
						Email:          usr.Email,
						EmailVerified:  usr.EmailVerified,
						ProviderUserID: usr.ProviderUserID,
						Name:           usr.Name,
						GivenName:      usr.GivenName,
						FamilyName:     usr.FamilyName,
						Picture:        usr.Picture,
						IsAdmin:        usr.IsAdmin,
					},
					ID: usr.ID,
				}
				if diff := cmp.Diff(tt.user, got); diff != "" {
					t.Errorf("GetByProviderUserID() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestUsers_GetByID(t *testing.T) {
	ctx := context.Background()
	providerID := uuid.NewString()
	userMock := domain.UserCreate{
		UserFields: domain.UserFields{
			Email:          "testuser@example.com",
			EmailVerified:  true,
			ProviderUserID: providerID,
			Name:           "test user name",
			GivenName:      "test given name",
			FamilyName:     "test family name",
			Picture:        "test-user-picture",
			IsAdmin:        false,
		},
		RefreshToken: "test-refresh-token",
	}

	tests := []struct {
		name          string
		user          domain.User
		before        func(t *testing.T) uuid.UUID
		cancelContext bool
		wantErr       error
	}{
		{
			name: "get user",
			user: domain.User{
				UserFields: domain.UserFields{
					Email:          "testuser@example.com",
					EmailVerified:  true,
					ProviderUserID: providerID,
					Name:           "test user name",
					GivenName:      "test given name",
					FamilyName:     "test family name",
					Picture:        "test-user-picture",
					IsAdmin:        false,
				},
			},
			before: func(t *testing.T) uuid.UUID {
				return seedUser(t, NewUsers(testClient), userMock)
			},
			wantErr: nil,
		},
		{
			name: "user not found",
			user: domain.User{
				UserFields: domain.UserFields{
					Email:          "testuser@example.com",
					EmailVerified:  true,
					ProviderUserID: providerID,
					Name:           "test user name",
					GivenName:      "test given name",
					FamilyName:     "test family name",
					Picture:        "test-user-picture",
					IsAdmin:        false,
				},
			},
			wantErr: ErrUserNotFound,
		},
		{
			name:          "returns an error when context is canceled",
			cancelContext: true,
			wantErr:       context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetUsers(t)

			if tt.before != nil {
				id := tt.before(t)
				tt.user.ID = id
			}

			testCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			usr, err := NewUsers(testClient).GetByID(testCtx, tt.user.ID)

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("GetByID() error = %v, want %v", err, tt.wantErr)
			}

			if tt.wantErr == nil {
				got := domain.User{
					UserFields: domain.UserFields{
						Email:          usr.Email,
						EmailVerified:  usr.EmailVerified,
						ProviderUserID: usr.ProviderUserID,
						Name:           usr.Name,
						GivenName:      usr.GivenName,
						FamilyName:     usr.FamilyName,
						Picture:        usr.Picture,
						IsAdmin:        usr.IsAdmin,
					},
					ID: usr.ID,
				}
				if diff := cmp.Diff(tt.user, got); diff != "" {
					t.Errorf("GetByID() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
