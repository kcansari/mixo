package routes

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type AuthResource struct {
	Auth           AuthHandler
	AuthMiddleware AuthMiddleware
}

type AuthHandler interface {
	Google(w http.ResponseWriter, r *http.Request)
	GoogleCallback(w http.ResponseWriter, r *http.Request)
	Logout(w http.ResponseWriter, r *http.Request)
}

type AuthMiddleware interface {
	RequireAuth(next http.Handler) http.Handler
	RequireAdmin(next http.Handler) http.Handler
}

func (ar AuthResource) Routes() chi.Router {
	r := chi.NewRouter()
	r.Route("/google", func(r chi.Router) {
		r.Get("/", ar.Auth.Google)
		r.Get("/callback", ar.Auth.GoogleCallback)
	})

	r.With(ar.AuthMiddleware.RequireAuth).Post("/logout", ar.Auth.Logout)
	return r
}
