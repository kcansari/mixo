package serializer

import (
	"net/http"

	"github.com/kcansari/mixo/internal/domain"
)

type UserResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	IsAdmin bool   `json:"isAdmin"`
}

func NewUserResponse(user *domain.User) *UserResponse {
	return &UserResponse{
		ID:      user.ID.String(),
		Name:    user.Name,
		Picture: user.Picture,
		IsAdmin: user.IsAdmin,
	}
}

// Render pro-processing before a response is marshalled and sent across the wire
func (u *UserResponse) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}
