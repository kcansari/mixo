package security

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

func TestJWTService_NewJWTService(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		wantErr error
	}{
		{
			name:    "valid secret",
			secret:  "secret",
			wantErr: nil,
		},
		{
			name:    "empty secret",
			secret:  "",
			wantErr: ErrSecretEmpty,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := NewJWTService(tt.secret)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("NewJWTService() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr == nil && string(j.secret) != tt.secret {
				t.Errorf("NewJWTService() secret = %s, want %s", string(j.secret), tt.secret)
			}
		})
	}
}

func TestJWTService_GenerateJWT(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		userID  uuid.UUID
		exp     time.Time
		wantErr error
	}{
		{
			name:    "valid token",
			secret:  "secret",
			userID:  uuid.New(),
			exp:     time.Now().Add(1 * time.Hour),
			wantErr: nil,
		},
		{
			name:    "empty userID",
			secret:  "secret",
			userID:  uuid.Nil,
			exp:     time.Now().Add(1 * time.Hour),
			wantErr: ErrUserIDCannotBeNil,
		},
		{
			name:    "empty expiration time",
			secret:  "secret",
			userID:  uuid.New(),
			exp:     time.Time{},
			wantErr: ErrExpirationTimeZero,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := NewJWTService(tt.secret)
			if err != nil {
				t.Fatalf("NewJWTService returned an error: %v", err)
			}
			got, gotErr := j.GenerateJWT(tt.userID, tt.exp)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("GenerateJWT() error = %v, wantErr %v", gotErr, tt.wantErr)
			}

			if got == "" && tt.wantErr == nil {
				t.Error("GenerateJWT() returned empty string")
			}
		})
	}
}

func TestJWTService_ParseJWT(t *testing.T) {
	userID := uuid.New()
	exp := time.Now().Add(1 * time.Hour)
	tests := []struct {
		name        string
		exp         time.Time
		modifyToken func(*string)
		claims      *CustomClaims
		wantErr     error
	}{
		{
			name: "valid token",
			exp:  exp,
			claims: &CustomClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   userID.String(),
					ExpiresAt: jwt.NewNumericDate(exp),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					Issuer:    JWTIssuer,
				},
			},
			wantErr: nil,
		},
		{
			name:    "expired token",
			exp:     time.Now().Add(-1 * time.Hour),
			claims:  nil,
			wantErr: jwt.ErrTokenExpired,
		},
		{
			name:   "malformed token",
			exp:    exp,
			claims: nil,
			modifyToken: func(token *string) {
				*token = *token + "-invalid"
			},
			wantErr: jwt.ErrTokenSignatureInvalid,
		},
		{
			name:   "empty token",
			exp:    exp,
			claims: nil,
			modifyToken: func(token *string) {
				*token = ""
			},
			wantErr: ErrTokenEmpty,
		},
		{
			name:   "malformed token",
			exp:    exp,
			claims: nil,
			modifyToken: func(token *string) {
				*token = ".-,??--invalid"
			},
			wantErr: jwt.ErrTokenMalformed,
		},
		{
			name:   "signed with wrong secret",
			exp:    exp,
			claims: nil,
			modifyToken: func(token *string) {
				j, err := NewJWTService("wrong-secret")
				if err != nil {
					t.Fatalf("NewJWTService returned an error: %v", err)
				}
				*token, err = j.GenerateJWT(userID, exp)
				if err != nil {
					t.Fatalf("GenerateJWT returned an error: %v", err)
				}
			},
			wantErr: jwt.ErrTokenSignatureInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j, err := NewJWTService("secret")
			if err != nil {
				t.Fatalf("NewJWTService returned an error: %v", err)
			}
			tokenString, err := j.GenerateJWT(userID, tt.exp)
			if err != nil {
				t.Fatalf("GenerateJWT returned an error: %v", err)
			}

			if tokenString == "" {
				t.Fatalf("GenerateJWT() returned empty string")
			}

			if tt.modifyToken != nil {
				tt.modifyToken(&tokenString)
			}

			customClaims, gotErr := j.ParseJWT(tokenString)
			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("ParseJWT returned an error: %v", gotErr)
			}

			if diff := cmp.Diff(customClaims, tt.claims); diff != "" {
				t.Errorf("claims mismatch (-want +got):\n%s", diff)
			}

		})
	}
}
