// Package httpx provides helpers for writing HTTP responses.
package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/render"
	"github.com/kcansari/mixo/internal/cache"
	"github.com/kcansari/mixo/internal/serializer"
	"github.com/kcansari/mixo/internal/store"
)

var (
	ErrUnauthorized = errors.New("unauthorized request")
	ErrForbidden    = errors.New("forbidden request")
)

// Render writes v to the response. A render failure means the connection
// is already broken, so the error is logged rather than returned.
func Render(w http.ResponseWriter, r *http.Request, v render.Renderer) {
	if err := render.Render(w, r, v); err != nil {
		slog.Error("render failure", "error", err)
	}
}

// ErrResponse is the JSON error payload returned to clients.
type ErrResponse struct {
	Err            error `json:"-"` // low-level runtime error
	HTTPStatusCode int   `json:"-"` // http response status code

	StatusText string `json:"status,omitempty"` // user-level status message
	ErrorText  string `json:"error,omitempty"`  // application-level error message, for debugging
}

func Internal(err error) render.Renderer {
	return &ErrResponse{
		Err:            err,
		HTTPStatusCode: http.StatusInternalServerError,
		StatusText:     http.StatusText(http.StatusInternalServerError),
		//ErrorText:      err.Error(),
	}
}

type clientError struct {
	status int
	kind   string
	level  slog.Level
}

var clientErrors = map[error]clientError{

	store.ErrUserNotFound:             {http.StatusNotFound, "not_found", slog.LevelInfo},
	store.ErrUserAlreadyExists:        {http.StatusConflict, "conflict", slog.LevelInfo},
	serializer.ErrGoogleCodeRequired:  {http.StatusBadRequest, "invalid_request", slog.LevelInfo},
	serializer.ErrGoogleStateRequired: {http.StatusBadRequest, "invalid_request", slog.LevelInfo},
	cache.ErrRedisKeyDoesNotExist:     {http.StatusNotFound, "not_found", slog.LevelInfo},
	http.ErrNoCookie:                  {http.StatusBadRequest, "no_cookie", slog.LevelInfo},
	ErrUnauthorized:                   {http.StatusUnauthorized, "unauthorized", slog.LevelInfo},
	ErrForbidden:                      {http.StatusForbidden, "forbidden", slog.LevelInfo},
}

func FromError(ctx context.Context, err error) render.Renderer {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if ce, ok := clientErrors[e]; ok {
			slog.Log(ctx, ce.level, "client error", "kind", ce.kind, "error", err)
			return &ErrResponse{
				Err:            err,
				HTTPStatusCode: ce.status,
				StatusText:     http.StatusText(ce.status),
				ErrorText:      e.Error(),
			}
		}
	}

	slog.ErrorContext(ctx, "internal error", "error", err)
	return Internal(err)
}

func (e *ErrResponse) Render(w http.ResponseWriter, r *http.Request) error {
	render.Status(r, e.HTTPStatusCode)
	return nil
}
