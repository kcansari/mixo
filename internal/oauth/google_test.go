package oauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kcansari/mixo/internal/oauth/mocks"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

func TestNewGoogleOAuth(t *testing.T) {
	t.Parallel()

	validConfig := GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/oauth/google/callback",
	}

	tests := []struct {
		name    string
		config  GoogleConfig
		want    *GoogleOAuth
		wantErr error
	}{
		{
			name:   "configures Google OAuth",
			config: validConfig,
			want: &GoogleOAuth{
				config: oauth2.Config{
					ClientID:     validConfig.ClientID,
					ClientSecret: validConfig.ClientSecret,
					RedirectURL:  validConfig.RedirectURL,
					Scopes:       []string{"openid", "email", "profile"},
					Endpoint: oauth2.Endpoint{
						AuthURL:  authURL,
						TokenURL: tokenURL,
					},
				},
			},
		},
		{
			name: "rejects empty client ID",
			config: GoogleConfig{
				ClientSecret: validConfig.ClientSecret,
				RedirectURL:  validConfig.RedirectURL,
			},
			wantErr: ErrGoogleClientIDRequired,
		},
		{
			name: "rejects whitespace-only client ID",
			config: GoogleConfig{
				ClientID:     " \t\n",
				ClientSecret: validConfig.ClientSecret,
				RedirectURL:  validConfig.RedirectURL,
			},
			wantErr: ErrGoogleClientIDRequired,
		},
		{
			name: "rejects empty client secret",
			config: GoogleConfig{
				ClientID:    validConfig.ClientID,
				RedirectURL: validConfig.RedirectURL,
			},
			wantErr: ErrGoogleClientSecretRequired,
		},
		{
			name: "rejects whitespace-only client secret",
			config: GoogleConfig{
				ClientID:     validConfig.ClientID,
				ClientSecret: " \t\n",
				RedirectURL:  validConfig.RedirectURL,
			},
			wantErr: ErrGoogleClientSecretRequired,
		},
		{
			name: "rejects empty redirect URL",
			config: GoogleConfig{
				ClientID:     validConfig.ClientID,
				ClientSecret: validConfig.ClientSecret,
			},
			wantErr: ErrGoogleRedirectURLRequired,
		},
		{
			name: "rejects whitespace-only redirect URL",
			config: GoogleConfig{
				ClientID:     validConfig.ClientID,
				ClientSecret: validConfig.ClientSecret,
				RedirectURL:  " \t\n",
			},
			wantErr: ErrGoogleRedirectURLRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := NewGoogleOAuth(tt.config)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewGoogleOAuth() error = %v, want %v", err, tt.wantErr)
			}
			if diff := cmp.Diff(
				tt.want,
				got,
				cmp.AllowUnexported(GoogleOAuth{}),
				cmpopts.IgnoreUnexported(oauth2.Config{}),
			); diff != "" {
				t.Errorf("NewGoogleOAuth() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGoogleOAuthGetRedirectURL(t *testing.T) {
	t.Parallel()

	config := GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/oauth/google/callback",
	}
	googleOAuth, err := NewGoogleOAuth(config)
	if err != nil {
		t.Fatalf("NewGoogleOAuth() error = %v, want nil", err)
	}

	verifier, state, redirectURL := googleOAuth.GetRedirectURL()

	if verifier == "" {
		t.Error("GetRedirectURL() verifier is empty")
	}
	if state == "" {
		t.Error("GetRedirectURL() state is empty")
	}

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", redirectURL, err)
	}

	wantAuthURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", authURL, err)
	}
	if parsedURL.Scheme != wantAuthURL.Scheme ||
		parsedURL.Host != wantAuthURL.Host ||
		parsedURL.Path != wantAuthURL.Path {
		t.Errorf(
			"GetRedirectURL() authorization endpoint = %q, want %q",
			parsedURL.Scheme+"://"+parsedURL.Host+parsedURL.Path,
			authURL,
		)
	}

	query := parsedURL.Query()
	wantQuery := map[string]string{
		"access_type":           "offline",
		"client_id":             config.ClientID,
		"code_challenge":        oauth2.S256ChallengeFromVerifier(verifier),
		"code_challenge_method": "S256",
		"redirect_uri":          config.RedirectURL,
		"response_type":         "code",
		"state":                 state,
	}
	for key, want := range wantQuery {
		if got := query.Get(key); got != want {
			t.Errorf("GetRedirectURL() query parameter %q = %q, want %q", key, got, want)
		}
	}

	wantScopes := []string{"openid", "email", "profile"}
	if diff := cmp.Diff(wantScopes, strings.Fields(query.Get("scope"))); diff != "" {
		t.Errorf("GetRedirectURL() scopes mismatch (-want +got):\n%s", diff)
	}

	secondVerifier, secondState, _ := googleOAuth.GetRedirectURL()
	if secondVerifier == verifier {
		t.Error("GetRedirectURL() returned the same verifier on consecutive calls")
	}
	if secondState == state {
		t.Error("GetRedirectURL() returned the same state on consecutive calls")
	}
}

func TestGoogleOAuthExchange(t *testing.T) {
	t.Parallel()

	const (
		code     = "authorization-code"
		verifier = "pkce-verifier"
	)

	config := GoogleConfig{
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		RedirectURL:  "https://example.com/oauth/google/callback",
	}

	tests := []struct {
		name          string
		statusCode    int
		response      string
		transportErr  error
		cancelContext bool
		wantToken     *oauth2.Token
		wantErr       bool
		wantErrIs     error
	}{
		{
			name:       "exchanges authorization code",
			statusCode: http.StatusOK,
			response: `{
				"access_token": "access-token",
				"token_type": "Bearer",
				"refresh_token": "refresh-token"
			}`,
			wantToken: &oauth2.Token{
				AccessToken:  "access-token",
				TokenType:    "Bearer",
				RefreshToken: "refresh-token",
			},
		},
		{
			name:       "returns error for invalid token JSON",
			statusCode: http.StatusOK,
			response:   `{"access_token":`,
			wantErr:    true,
		},
		{
			name:       "returns error for HTTP error status",
			statusCode: http.StatusBadRequest,
			response:   `{"error":"invalid_grant"}`,
			wantErr:    true,
		},
		{
			name:         "returns error for transport failure",
			transportErr: errors.New("transport failed"),
			wantErr:      true,
		},
		{
			name:          "returns error when context is canceled",
			statusCode:    http.StatusOK,
			cancelContext: true,
			wantErr:       true,
			wantErrIs:     context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			transport := mocks.NewMockRoundTripper(ctrl)

			type contextKey struct{}
			ctx := context.WithValue(context.Background(), contextKey{}, "supplied-context")
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			if tt.cancelContext {
				cancel()
			}

			transport.EXPECT().
				RoundTrip(gomock.Any()).
				DoAndReturn(func(req *http.Request) (*http.Response, error) {
					if req.Method != http.MethodPost {
						t.Errorf("Exchange() method = %q, want %q", req.Method, http.MethodPost)
					}
					if req.URL.String() != tokenURL {
						t.Errorf("Exchange() URL = %q, want %q", req.URL.String(), tokenURL)
					}
					if got := req.Context().Value(contextKey{}); got != "supplied-context" {
						t.Errorf("Exchange() context value = %v, want %q", got, "supplied-context")
					}
					if err := req.ParseForm(); err != nil {
						t.Errorf("ParseForm() error = %v", err)
						return nil, err
					}
					wantForm := map[string]string{
						"code":          code,
						"code_verifier": verifier,
						"redirect_uri":  config.RedirectURL,
					}
					for key, want := range wantForm {
						if got := req.PostForm.Get(key); got != want {
							t.Errorf("Exchange() form value %q = %q, want %q", key, got, want)
						}
					}

					if tt.transportErr != nil {
						return nil, tt.transportErr
					}
					if err := req.Context().Err(); err != nil {
						return nil, err
					}
					response := newHTTPResponse(t, tt.statusCode, tt.response)
					response.Header.Set("Content-Type", "application/json")
					return response, nil
				}).
				MinTimes(1)

			httpClient := &http.Client{Transport: transport}
			ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)

			googleOAuth, err := NewGoogleOAuth(GoogleConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "https://example.com/oauth/google/callback",
			})
			if err != nil {
				t.Fatalf("NewGoogleOAuth() error = %v, want nil", err)
			}

			gotToken, err := googleOAuth.Exchange(ctx, code, verifier)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Exchange() error = nil, want non-nil")
				}
			} else if err != nil {
				t.Fatalf("Exchange() error = %v, want nil", err)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("Exchange() error = %v, want %v", err, tt.wantErrIs)
			}

			if diff := cmp.Diff(
				tt.wantToken,
				gotToken,
				cmpopts.IgnoreUnexported(oauth2.Token{}),
			); diff != "" {
				t.Errorf("Exchange() token mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGoogleOAuthGetUserInfo(t *testing.T) {
	t.Parallel()

	token := &oauth2.Token{AccessToken: "access-token"}
	transportErr := errors.New("transport failed")

	tests := []struct {
		name          string
		statusCode    int
		responseBody  string
		transportErr  error
		cancelContext bool
		nilContext    bool
		want          GoogleUserInfo
		wantErr       bool
		wantErrIs     error
	}{
		{
			name:       "returns complete user information",
			statusCode: http.StatusOK,
			responseBody: `{
				"id": "google-user-id",
				"email": "user@example.com",
				"verified_email": true,
				"name": "Example User",
				"given_name": "Example",
				"family_name": "User",
				"picture": "https://example.com/picture.jpg"
			}`,
			want: GoogleUserInfo{
				ID:            "google-user-id",
				Email:         "user@example.com",
				EmailVerified: true,
				Name:          "Example User",
				GivenName:     "Example",
				FamilyName:    "User",
				Picture:       "https://example.com/picture.jpg",
			},
		},
		{
			name:         "returns required user information",
			statusCode:   http.StatusOK,
			responseBody: `{"id":"google-user-id","email":"user@example.com"}`,
			want: GoogleUserInfo{
				ID:    "google-user-id",
				Email: "user@example.com",
			},
		},
		{
			name:         "returns error when user ID is missing",
			statusCode:   http.StatusOK,
			responseBody: `{"email":"user@example.com"}`,
			wantErr:      true,
			wantErrIs:    ErrGoogleProviderUserIDRequired,
		},
		{
			name:         "returns error when email is missing",
			statusCode:   http.StatusOK,
			responseBody: `{"id":"google-user-id"}`,
			wantErr:      true,
			wantErrIs:    ErrGoogleEmailRequired,
		},
		{
			name:         "returns error for non-200 response",
			statusCode:   http.StatusUnauthorized,
			responseBody: `{"error":"unauthorized"}`,
			wantErr:      true,
		},
		{
			name:         "returns error for malformed JSON",
			statusCode:   http.StatusOK,
			responseBody: `{"id":`,
			wantErr:      true,
		},
		{
			name:         "returns error for transport failure",
			transportErr: transportErr,
			wantErr:      true,
		},
		{
			name:          "returns error for cancelled context",
			cancelContext: true,
			wantErr:       true,
			wantErrIs:     context.Canceled,
		},
		{
			name:       "returns error for nil context",
			nilContext: true,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			transport := mocks.NewMockRoundTripper(ctrl)

			type contextKey struct{}
			var ctx context.Context
			if !tt.nilContext {
				ctx = context.WithValue(context.Background(), contextKey{}, "supplied-context")
				cancelCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				ctx = cancelCtx
				if tt.cancelContext {
					cancel()
				}

				transport.EXPECT().
					RoundTrip(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						if req.Method != http.MethodGet {
							t.Errorf("GetUserInfo() method = %q, want %q", req.Method, http.MethodGet)
						}
						if req.URL.String() != "https://www.googleapis.com/oauth2/v2/userinfo" {
							t.Errorf(
								"GetUserInfo() URL = %q, want Google user-info URL",
								req.URL.String(),
							)
						}
						if got := req.Header.Get("Authorization"); got != "Bearer access-token" {
							t.Errorf("GetUserInfo() Authorization = %q, want %q", got, "Bearer access-token")
						}
						if got := req.Context().Value(contextKey{}); got != "supplied-context" {
							t.Errorf("GetUserInfo() context value = %v, want %q", got, "supplied-context")
						}

						if tt.transportErr != nil {
							return nil, tt.transportErr
						}
						if err := req.Context().Err(); err != nil {
							return nil, err
						}
						return newHTTPResponse(t, tt.statusCode, tt.responseBody), nil
					})

				httpClient := &http.Client{Transport: transport}
				ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
			}

			googleOAuth, err := NewGoogleOAuth(GoogleConfig{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "https://example.com/oauth/google/callback",
			})
			if err != nil {
				t.Fatalf("NewGoogleOAuth() error = %v, want nil", err)
			}

			got, err := googleOAuth.GetUserInfo(ctx, token)
			if tt.wantErr {
				if err == nil {
					t.Fatal("GetUserInfo() error = nil, want non-nil")
				}
			} else if err != nil {
				t.Fatalf("GetUserInfo() error = %v, want nil", err)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("GetUserInfo() error = %v, want %v", err, tt.wantErrIs)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("GetUserInfo() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func newHTTPResponse(t *testing.T, statusCode int, body string) *http.Response {
	t.Helper()

	return &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
