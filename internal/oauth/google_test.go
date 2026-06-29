package oauth

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kcansari/mixo/internal/oauth/mocks"
	"go.uber.org/mock/gomock"
	"google.golang.org/api/idtoken"
)

func TestGoogleOAuth_VerifyIDToken(t *testing.T) {
	token := "token"
	clientID := "clientID"
	errValidator := errors.New("validator error")
	userInfo := GoogleUserInfo{
		ID:            "123456789",
		Email:         "test@example.com",
		EmailVerified: true,
		Name:          "Test User",
		GivenName:     "Test",
		FamilyName:    "User",
		Picture:       "https://example.com/picture.jpg",
	}
	optionalUserInfo := GoogleUserInfo{
		ID:      "123456789",
		Email:   userInfo.Email,
		Name:    userInfo.Name,
		Picture: userInfo.Picture,
	}
	tests := []struct {
		name    string
		setup   func(*mocks.MockIDTokenValidator)
		want    *GoogleUserInfo
		wantErr error
	}{
		{
			name:    "valid token",
			want:    &userInfo,
			wantErr: nil,
			setup: func(MockIDTokenValidator *mocks.MockIDTokenValidator) {
				MockIDTokenValidator.EXPECT().
					Validate(context.Background(), token, clientID).
					Return(&idtoken.Payload{
						Subject: userInfo.ID,
						Claims: map[string]interface{}{
							"email":          userInfo.Email,
							"email_verified": userInfo.EmailVerified,
							"name":           userInfo.Name,
							"given_name":     userInfo.GivenName,
							"family_name":    userInfo.FamilyName,
							"picture":        userInfo.Picture,
						},
					}, nil)
			},
		},
		{
			name:    "validator returns error",
			want:    nil,
			wantErr: errValidator,
			setup: func(MockIDTokenValidator *mocks.MockIDTokenValidator) {
				MockIDTokenValidator.EXPECT().
					Validate(context.Background(), token, clientID).
					Return(nil, errValidator)
			},
		},
		{
			name:    "empty subject",
			want:    nil,
			wantErr: ErrEmptySubject,
			setup: func(MockIDTokenValidator *mocks.MockIDTokenValidator) {
				MockIDTokenValidator.EXPECT().
					Validate(context.Background(), token, clientID).
					Return(&idtoken.Payload{
						Subject: "",
						Claims:  map[string]interface{}{},
					}, nil)
			},
		},
		{
			name:    "empty payload",
			want:    nil,
			wantErr: ErrEmptyPayload,
			setup: func(MockIDTokenValidator *mocks.MockIDTokenValidator) {
				MockIDTokenValidator.EXPECT().
					Validate(context.Background(), token, clientID).
					Return(nil, nil)
			},
		},
		{
			name:    "invalid email claim",
			want:    nil,
			wantErr: ErrInvalidEmailClaim,
			setup: func(MockIDTokenValidator *mocks.MockIDTokenValidator) {
				MockIDTokenValidator.EXPECT().
					Validate(context.Background(), token, clientID).
					Return(&idtoken.Payload{
						Subject: "test",
						Claims: map[string]interface{}{
							"email": "",
						},
					}, nil)
			},
		},
		{
			name:    "optinal string claim",
			want:    &optionalUserInfo,
			wantErr: nil,
			setup: func(MockIDTokenValidator *mocks.MockIDTokenValidator) {
				MockIDTokenValidator.EXPECT().
					Validate(context.Background(), token, clientID).
					Return(&idtoken.Payload{
						Subject: optionalUserInfo.ID,
						Claims: map[string]interface{}{
							"email":   optionalUserInfo.Email,
							"name":    optionalUserInfo.Name,
							"picture": optionalUserInfo.Picture,
						},
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockIDTokenValidator := mocks.NewMockIDTokenValidator(ctrl)

			if tt.setup != nil {
				tt.setup(mockIDTokenValidator)
			}

			oauthSvc, err := NewGoogleOAuth(clientID, mockIDTokenValidator)
			if err != nil {
				t.Fatalf("NewGoogleOAuth() error = %v", err)
			}

			got, err := oauthSvc.VerifyIDToken(context.Background(), token)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("VerifyIDToken() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr == nil {
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("VerifyIDToken() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func Test_stringClaim(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   string
		want2  bool
	}{
		{
			name: "get exist key",
			claims: map[string]any{
				"key": "value",
			},
			key:   "key",
			want:  "value",
			want2: true,
		},
		{
			name: "get non-exist key",
			claims: map[string]any{
				"key": "value",
			},
			key:   "non-exist-key",
			want:  "",
			want2: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got2 := stringClaim(tt.claims, tt.key)
			if got != tt.want {
				t.Errorf("stringClaim() = %v, want %v", got, tt.want)
			}
			if got2 != tt.want2 {
				t.Errorf("stringClaim() = %v, want %v", got2, tt.want2)
			}
		})
	}
}

func Test_optionalStringClaim(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   string
	}{
		{
			name: "get exist key",
			claims: map[string]any{
				"key": "value",
			},
			key:  "key",
			want: "value",
		},
		{
			name: "get non-exist key",
			claims: map[string]any{
				"key": "value",
			},
			key:  "non-exist-key",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := optionalStringClaim(tt.claims, tt.key)
			if got != tt.want {
				t.Errorf("optionalStringClaim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_boolClaim(t *testing.T) {
	tests := []struct {
		name   string
		claims map[string]any
		key    string
		want   bool
	}{
		{
			name: "get exist key",
			claims: map[string]any{
				"key": true,
			},
			key:  "key",
			want: true,
		},
		{
			name: "get non-exist key",
			claims: map[string]any{
				"key": true,
			},
			key:  "non-exist-key",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boolClaim(tt.claims, tt.key)
			if got != tt.want {
				t.Errorf("boolClaim() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewGoogleOAuth(t *testing.T) {
	clientID := "client-id"
	tests := []struct {
		name      string
		clientID  string
		validator IDTokenValidator
		wantErr   error
	}{
		{
			name:     "correct init",
			clientID: clientID,
			validator: func() IDTokenValidator {
				ctrl := gomock.NewController(t)
				return mocks.NewMockIDTokenValidator(ctrl)
			}(),
			wantErr: nil,
		},
		{
			name:      "empty client id",
			clientID:  "",
			validator: nil,
			wantErr:   ErrGoogleClientIDRequired,
		},
		{
			name:      "nil validator",
			clientID:  clientID,
			validator: nil,
			wantErr:   ErrIDTokenValidatorRequired,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := NewGoogleOAuth(tt.clientID, tt.validator)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("NewGoogleOAuth() error = %v, wantErr %v", gotErr, tt.wantErr)
			}

			if tt.wantErr != nil {
				return
			}

			if got == nil {
				t.Fatal("NewGoogleOAuth() = nil, want GoogleOAuth")
			}

			if got.ClientID != tt.clientID {
				t.Errorf("NewGoogleOAuth().ClientID = %q, want %q", got.ClientID, tt.clientID)
			}

			if got.validator == nil {
				t.Error("NewGoogleOAuth().validator = nil, want validator")
			}
		})
	}
}
