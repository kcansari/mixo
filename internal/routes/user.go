package routes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type UserResource struct {
	User           UserHandler
	AuthMiddleware AuthMiddleware
}

type UserHandler interface {
	GetUser(w http.ResponseWriter, r *http.Request)
}

func (ur UserResource) Routes() chi.Router {
	r := chi.NewRouter()
	r.Use(ur.AuthMiddleware.RequireAuth)

	r.Get("/me", ur.User.GetUser)

	return r
}
