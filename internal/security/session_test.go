package security

import (
	context "context"
	"errors"
	"log/slog"
	"testing"
	time "time"

	"go.uber.org/mock/gomock"
)

func Test_generateSessionID(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "get random session id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateSessionID()
			slog.Info("session id", "seessionID", got)
			if got == "" {
				t.Errorf("generateSessionID() = %v, want non-empty", got)
			}
		})
	}
}

func TestSession_Create(t *testing.T) {
	ErrCacheKeyCreator := errors.New("failed to create key")
	ErrCacheSet := errors.New("failed to set cache")
	signedSID := "signed-session-id"
	key := "key-value"
	value := "random-value"
	tests := []struct {
		name    string
		value   string
		setup   func(*MockCache, *MockHMAC)
		want    string
		wantErr error
	}{
		{
			name: "succes create",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(gomock.Any()).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					Set(gomock.Any(), key, value, DefaultSessionExpiration).
					Return(nil).
					Times(1)
			},
		},
		{
			name: "failed with KeyCreator",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(gomock.Any()).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return("", ErrCacheKeyCreator)
			},
			wantErr: ErrCacheKeyCreator,
		},
		{
			name: "failed with Cache Set",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(gomock.Any()).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					Set(gomock.Any(), key, value, DefaultSessionExpiration).
					Return(ErrCacheSet).
					Times(1)
			},
			wantErr: ErrCacheSet,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cacheMock := NewMockCache(ctrl)
			hmacMock := NewMockHMAC(ctrl)

			tt.setup(cacheMock, hmacMock)

			session := NewSession(cacheMock, hmacMock)

			_, gotErr := session.Create(context.Background(), value)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("Create() error = %v, want %v", gotErr, tt.wantErr)
			}

		})
	}
}

func TestSession_Get(t *testing.T) {
	ErrCacheKeyCreator := errors.New("failed to create key")
	sid := "session-id"
	signedSID := "signed-session-id"
	key := "key-value"
	value := "random-value"
	tests := []struct {
		name    string
		sid     string
		value   string
		setup   func(*MockCache, *MockHMAC)
		want    string
		wantErr error
	}{
		{
			name: "succes get",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					Get(gomock.Any(), key).
					Return(value, nil).
					Times(1)
			},
			sid:  sid,
			want: value,
		},
		{
			name:    "failed with empty sid",
			sid:     "",
			wantErr: ErrSessionIDRequired,
		},
		{
			name: "failed with KeyCreator",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(gomock.Any()).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return("", ErrCacheKeyCreator)
			},
			sid:     sid,
			wantErr: ErrCacheKeyCreator,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cacheMock := NewMockCache(ctrl)
			hmacMock := NewMockHMAC(ctrl)

			if tt.setup != nil {
				tt.setup(cacheMock, hmacMock)
			}

			session := NewSession(cacheMock, hmacMock)

			got, gotErr := session.Get(context.Background(), tt.sid)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("Get() error = %v, want %v", gotErr, tt.wantErr)
			}

			if got != tt.want {
				t.Fatalf("Get() got = %v, want %v", got, tt.want)
			}

		})
	}
}

func TestSession_Destroy(t *testing.T) {
	ErrCacheKeyCreator := errors.New("failed to create key")
	sid := "session-id"
	signedSID := "signed-session-id"
	key := "key-value"
	tests := []struct {
		name    string
		sid     string
		value   string
		setup   func(*MockCache, *MockHMAC)
		wantErr error
	}{
		{
			name: "succes destroy",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					Delete(gomock.Any(), key).
					Return(nil).
					Times(1)
			},
			sid: sid,
		},
		{
			name:    "failed with empty sid",
			sid:     "",
			wantErr: ErrSessionIDRequired,
		},
		{
			name: "failed with KeyCreator",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(gomock.Any()).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return("", ErrCacheKeyCreator)
			},
			sid:     sid,
			wantErr: ErrCacheKeyCreator,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cacheMock := NewMockCache(ctrl)
			hmacMock := NewMockHMAC(ctrl)

			if tt.setup != nil {
				tt.setup(cacheMock, hmacMock)
			}

			session := NewSession(cacheMock, hmacMock)

			gotErr := session.Destroy(context.Background(), tt.sid)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("Destroy() error = %v, want %v", gotErr, tt.wantErr)
			}

		})
	}
}

func TestSession_ShouldExtend(t *testing.T) {
	ErrCacheKeyCreator := errors.New("failed to create key")
	ErrCacheTTL := errors.New("failed to get ttl")
	sid := "session-id"
	signedSID := "signed-session-id"
	key := "key-value"
	tests := []struct {
		name    string
		sid     string
		want    bool
		setup   func(*MockCache, *MockHMAC)
		wantErr error
	}{
		{
			name: "need extend",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					TTL(gomock.Any(), key).
					Return(DefaultSessionExpiration/2, nil).
					Times(1)
			},
			sid:  sid,
			want: true,
		},
		{
			name: "no need extend",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					TTL(gomock.Any(), key).
					Return(DefaultSessionExpiration, nil).
					Times(1)
			},
			sid:  sid,
			want: false,
		},
		{
			name:    "empty sid",
			sid:     "",
			want:    false,
			wantErr: ErrSessionIDRequired,
		},
		{
			name: "key creator error",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return("", ErrCacheKeyCreator)
			},
			sid:     sid,
			want:    false,
			wantErr: ErrCacheKeyCreator,
		},
		{
			name: "cache ttl error",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					TTL(gomock.Any(), key).
					Return(0*time.Second, ErrCacheTTL).
					Times(1)
			},
			sid:     sid,
			want:    false,
			wantErr: ErrCacheTTL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cacheMock := NewMockCache(ctrl)
			hmacMock := NewMockHMAC(ctrl)

			if tt.setup != nil {
				tt.setup(cacheMock, hmacMock)
			}

			session := NewSession(cacheMock, hmacMock)

			got, gotErr := session.ShouldExtend(context.Background(), tt.sid)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("ShouldExtend() error = %v, want error = %v", gotErr, tt.wantErr)
			}

			if got != tt.want {
				t.Fatalf("ShouldExtend() got = %v, want %v", got, tt.want)
			}

		})
	}
}

func TestSession_Extend(t *testing.T) {
	var (
		ErrCacheKeyCreator = errors.New("failed to create key")
	)
	sid := "session-id"
	signedSID := "signed-session-id"
	key := "key-value"
	tests := []struct {
		name    string
		sid     string
		setup   func(*MockCache, *MockHMAC)
		wantErr error
	}{
		{
			name: "extend success",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					Expire(gomock.Any(), key, DefaultSessionExpiration).
					Return(true, nil).
					Times(1)
			},
			sid:     sid,
			wantErr: nil,
		},
		{
			name:    "empty sid",
			sid:     "",
			wantErr: ErrSessionIDRequired,
		},
		{
			name: "key creator error",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return("", ErrCacheKeyCreator)
			},
			sid:     sid,
			wantErr: ErrCacheKeyCreator,
		},
		{
			name: "session not found",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

				cacheMock.EXPECT().
					Expire(gomock.Any(), key, DefaultSessionExpiration).
					Return(false, nil).
					Times(1)
			},
			sid:     sid,
			wantErr: ErrSessionNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cacheMock := NewMockCache(ctrl)
			hmacMock := NewMockHMAC(ctrl)

			if tt.setup != nil {
				tt.setup(cacheMock, hmacMock)
			}

			session := NewSession(cacheMock, hmacMock)

			gotErr := session.Extend(context.Background(), tt.sid)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("Extend() error = %v, want error = %v", gotErr, tt.wantErr)
			}

		})
	}
}

func TestSession_getKey(t *testing.T) {
	var (
		ErrCacheKeyCreator = errors.New("failed to create key")
	)
	sid := "session-id"
	signedSID := "signed-session-id"
	key := "key-value"
	tests := []struct {
		name    string
		sid     string
		setup   func(*MockCache, *MockHMAC)
		wantErr error
		want    string
	}{
		{
			name: "get key success",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return(key, nil)

			},
			sid:     sid,
			wantErr: nil,
			want:    key,
		},
		{
			name:    "empty sid",
			sid:     "",
			wantErr: ErrSessionIDRequired,
		},
		{
			name: "key creator error",
			setup: func(cacheMock *MockCache, hmacMock *MockHMAC) {
				hmacMock.EXPECT().
					Sign(sid).
					Return(signedSID).
					Times(1)

				cacheMock.EXPECT().
					KeyCreator(SessionPrefix, signedSID).
					Return("", ErrCacheKeyCreator)
			},
			sid:     sid,
			wantErr: ErrCacheKeyCreator,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			cacheMock := NewMockCache(ctrl)
			hmacMock := NewMockHMAC(ctrl)

			if tt.setup != nil {
				tt.setup(cacheMock, hmacMock)
			}

			session := NewSession(cacheMock, hmacMock)

			got, gotErr := session.getKey(tt.sid)

			if !errors.Is(gotErr, tt.wantErr) {
				t.Fatalf("Extend() error = %v, want error = %v", gotErr, tt.wantErr)
			}

			if got != tt.want {
				t.Fatalf("Extend() got = %v, want = %v", got, tt.want)
			}

		})
	}
}
