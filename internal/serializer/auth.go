package serializer

import (
	"errors"
	"net/http"
	"strings"
)

var (
	ErrGoogleCodeRequired  = errors.New("googleOAuth code is required")
	ErrGoogleStateRequired = errors.New("googleOAuth state is required")
)

type GoogleCallbackRequest struct {
	Code  string
	State string
	Error string
}

func (g *GoogleCallbackRequest) BindQuery(r *http.Request) error {

	q := r.URL.Query()

	g.Code = strings.TrimSpace(q.Get("code"))
	g.State = strings.TrimSpace(q.Get("state"))
	g.Error = strings.TrimSpace(q.Get("error"))

	if g.Error != "" {
		return nil
	}

	if g.Code == "" {
		return ErrGoogleCodeRequired
	}
	if g.State == "" {
		return ErrGoogleStateRequired
	}
	return nil
}
