//go:generate mockgen -destination=mocks/google_mocks.go -package=mocks net/http RoundTripper
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

const (
	authURL  = "https://accounts.google.com/o/oauth2/auth"
	tokenURL = "https://oauth2.googleapis.com/token"
)

var (
	ErrGoogleClientIDRequired       = errors.New("googleOAuth client_id is required")
	ErrGoogleClientSecretRequired   = errors.New("googleOAuth client_secret is required")
	ErrGoogleRedirectURLRequired    = errors.New("googleOAuth redirect_url is required")
	ErrGoogleProviderUserIDRequired = errors.New("googleOAuth provider user id is required")
	ErrGoogleEmailRequired          = errors.New("googleOAuth email is required")
	ErrInvalidCode                  = errors.New("googleOAuth invalid code")
	ErrInvalidVerifier              = errors.New("googleOAuth invalid verifier")
)

type GoogleOAuth struct {
	config oauth2.Config
}

type GoogleConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

func NewGoogleOAuth(config GoogleConfig) (*GoogleOAuth, error) {

	if strings.TrimSpace(config.ClientID) == "" {
		return nil, ErrGoogleClientIDRequired
	}
	if strings.TrimSpace(config.ClientSecret) == "" {
		return nil, ErrGoogleClientSecretRequired
	}
	if strings.TrimSpace(config.RedirectURL) == "" {
		return nil, ErrGoogleRedirectURLRequired
	}

	oauth2Config := oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}
	return &GoogleOAuth{
		config: oauth2Config,
	}, nil
}

func (g *GoogleOAuth) GetRedirectURL() (verifier, state, url string) {
	// use PKCE to protect against CSRF attacks
	// https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-22.html#name-countermeasures-6
	verifier = oauth2.GenerateVerifier()
	state = rand.Text()

	url = g.config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
	return verifier, state, url
}

func (g *GoogleOAuth) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("oauth.google.Exchange: %w", ErrInvalidCode)
	}
	if strings.TrimSpace(verifier) == "" {
		return nil, fmt.Errorf("oauth.google.Exchange: %w", ErrInvalidVerifier)
	}
	token, err := g.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("ouath.google.Exchange: exchange token: %w", err)
	}
	return token, nil
}

func (g *GoogleOAuth) GetUserInfo(ctx context.Context, token *oauth2.Token) (user GoogleUserInfo, err error) {
	const userInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return GoogleUserInfo{}, fmt.Errorf("ouath.google.GetUserInfo: create request: %w", err)
	}

	resp, err := g.config.Client(ctx, token).Do(req)
	if err != nil {
		return GoogleUserInfo{}, fmt.Errorf("ouath.google.GetUserInfo: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GoogleUserInfo{}, fmt.Errorf("ouath.google.GetUserInfo: status code: %d", resp.StatusCode)
	}

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return GoogleUserInfo{}, err
	}

	if userInfo.ID == "" {
		return GoogleUserInfo{},
			fmt.Errorf("ouath.google.GetUserInfo: %w", ErrGoogleProviderUserIDRequired)
	}
	if userInfo.Email == "" {
		return GoogleUserInfo{},
			fmt.Errorf("ouath.google.GetUserInfo: %w", ErrGoogleEmailRequired)
	}

	return GoogleUserInfo{
		ID:            userInfo.ID,
		Email:         userInfo.Email,
		EmailVerified: userInfo.EmailVerified,
		Name:          userInfo.Name,
		GivenName:     userInfo.GivenName,
		FamilyName:    userInfo.FamilyName,
		Picture:       userInfo.Picture,
	}, nil
}
