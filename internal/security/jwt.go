package security

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrUserIDCannotBeNil  = errors.New("security.jwt.GenerateJWT: userID is nil")
	ErrExpirationTimeZero = errors.New("security.jwt.GenerateJWT: expiration time is zero")
	ErrSecretEmpty        = errors.New("security.jwt.NewJWTService: secret is empty")
	ErrTokenEmpty         = errors.New("security.jwt.ParseJWT: token is empty")
)

const (
	JWTIssuer = "mixo"
)

type CustomClaims struct {
	jwt.RegisteredClaims
}

type JWTService struct {
	secret []byte
}

func NewJWTService(secret string) (*JWTService, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, ErrSecretEmpty
	}
	return &JWTService{
		secret: []byte(secret),
	}, nil
}

func (j *JWTService) GenerateJWT(userID uuid.UUID, exp time.Time) (string, error) {

	if userID == uuid.Nil {
		return "", ErrUserIDCannotBeNil
	}

	if exp.IsZero() {
		return "", ErrExpirationTimeZero
	}

	claims := CustomClaims{
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    JWTIssuer,
			Subject:   userID.String(),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := t.SignedString(j.secret)

	if err != nil {
		return "", fmt.Errorf("security.jwt.GenerateJWT: userID=%s %w", userID, err)
	}

	return s, nil
}

func (j *JWTService) ParseJWT(t string) (*CustomClaims, error) {

	if strings.TrimSpace(t) == "" {
		return nil, ErrTokenEmpty
	}

	token, err := jwt.ParseWithClaims(t, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		return j.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("security.jwt.ParseJWT: %w", err)
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("parse jwt: invalid claims type")
	}

	return claims, nil
}
