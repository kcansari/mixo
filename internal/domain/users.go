package domain

import "github.com/google/uuid"

type UserFields struct {
	Email          string
	ProviderUserID string
	EmailVerified  bool
	Name           string
	GivenName      string
	FamilyName     string
	Picture        string
	IsAdmin        bool
}

type UserCreate struct {
	UserFields
	RefreshToken string
}

type User struct {
	ID uuid.UUID
	UserFields
}
