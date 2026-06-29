package serializer

import (
	"errors"
	"net/http"
	"strings"
)

var (
	ErrGoogleCodeRequired   = errors.New("googleOAuth code is required")
	ErrGoogleStateRequired  = errors.New("googleOAuth state is required")
	ErrGoogleTokenRequired  = errors.New("googleOAuth token is required")
	ErrRefreshTokenRequired = errors.New("refresh token is required")
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

type GoogleVerifyRequest struct {
	Token string `json:"idToken"`
}

type GoogleVerifyResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func (g *GoogleVerifyRequest) Bind(r *http.Request) error {

	if strings.TrimSpace(g.Token) == "" {
		return ErrGoogleTokenRequired
	}
	return nil
}

func NewGoogleVerifyResponse(accessToken, refreshToken string) *GoogleVerifyResponse {
	return &GoogleVerifyResponse{AccessToken: accessToken, RefreshToken: refreshToken}
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (rr *RefreshRequest) Bind(r *http.Request) error {
	if strings.TrimSpace(rr.RefreshToken) == "" {
		return ErrRefreshTokenRequired
	}
	return nil
}

type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func NewRefreshResponse(accessToken, refreshToken string) *RefreshResponse {
	return &RefreshResponse{AccessToken: accessToken, RefreshToken: refreshToken}
}
