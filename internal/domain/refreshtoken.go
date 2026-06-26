package domain

import (
	"time"

	"github.com/google/uuid"
)

const DefaultAccessTokenExpiration = 60 * time.Minute
const DefaultRefreshTokenExpiration = 7 * 24 * time.Hour

type RefreshToken struct {
	UserID    uuid.UUID
	TokenHash string
	RevokedAt *time.Time
	CreatedAt time.Time
}

type Tokens struct {
	AccessToken  string
	RefreshToken string
}
