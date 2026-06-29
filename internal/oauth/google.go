//go:generate mockgen -source=google.go -destination=mocks/google_mocks.go -package=mocks
package oauth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/api/idtoken"
)

var (
	ErrGoogleClientIDRequired   = errors.New("googleOAuth client_id is required")
	ErrEmptySubject             = errors.New("payload subject is empty")
	ErrIDTokenValidatorRequired = errors.New("googleOAuth validator is required")
	ErrInvalidEmailClaim        = errors.New("email claim is missing or empty")
	ErrEmptyPayload             = errors.New("idtoken verify payload is nil")
)

type GoogleOAuth struct {
	ClientID  string
	validator IDTokenValidator
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

type IDTokenValidator interface {
	Validate(ctx context.Context, token string, audience string) (*idtoken.Payload, error)
}

func NewGoogleOAuth(clientID string, validator IDTokenValidator) (*GoogleOAuth, error) {

	if strings.TrimSpace(clientID) == "" {
		return nil, ErrGoogleClientIDRequired
	}

	if validator == nil {
		return nil, ErrIDTokenValidatorRequired
	}

	return &GoogleOAuth{
		ClientID:  clientID,
		validator: validator,
	}, nil
}

func (g *GoogleOAuth) VerifyIDToken(ctx context.Context, token string) (*GoogleUserInfo, error) {
	payload, err := g.validator.Validate(ctx, token, g.ClientID)
	if err != nil {
		return nil, fmt.Errorf("oauth.google.VerifyIDToken: validate token: %w", err)
	}

	if payload == nil {
		return nil, ErrEmptyPayload
	}

	if strings.TrimSpace(payload.Subject) == "" {
		return nil, ErrEmptySubject
	}

	email, ok := stringClaim(payload.Claims, "email")
	if !ok || strings.TrimSpace(email) == "" {
		return nil, ErrInvalidEmailClaim
	}

	userInfo := GoogleUserInfo{
		ID:            payload.Subject,
		Email:         email,
		EmailVerified: boolClaim(payload.Claims, "email_verified"),
		Name:          optionalStringClaim(payload.Claims, "name"),
		GivenName:     optionalStringClaim(payload.Claims, "given_name"),
		FamilyName:    optionalStringClaim(payload.Claims, "family_name"),
		Picture:       optionalStringClaim(payload.Claims, "picture"),
	}

	return &userInfo, nil
}

func stringClaim(claims map[string]any, key string) (string, bool) {
	value, ok := claims[key].(string)
	return value, ok
}

func optionalStringClaim(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return value
}

func boolClaim(claims map[string]any, key string) bool {
	value, _ := claims[key].(bool)
	return value
}

type DefaultIDTokenValidator struct{}

func (DefaultIDTokenValidator) Validate(ctx context.Context, token string, audience string) (*idtoken.Payload, error) {
	return idtoken.Validate(ctx, token, audience)
}
