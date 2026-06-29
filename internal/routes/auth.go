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
	Logout(w http.ResponseWriter, r *http.Request)
	Verify(w http.ResponseWriter, r *http.Request)
	Refresh(w http.ResponseWriter, r *http.Request)
}

type AuthMiddleware interface {
	RequireAuth(next http.Handler) http.Handler
	RequireAdmin(next http.Handler) http.Handler
}

func (ar AuthResource) Routes() chi.Router {
	r := chi.NewRouter()
	r.Route("/google", func(r chi.Router) {
		r.Post("/verify", ar.Auth.Verify)
	})
	r.Post("/refresh", ar.Auth.Refresh)

	r.With(ar.AuthMiddleware.RequireAuth).Post("/logout", ar.Auth.Logout)
	return r
}
