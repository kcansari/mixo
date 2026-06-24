package security_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kcansari/mixo/internal/security"
)

const (
	key128   = "0123456789abcdef0123456789abcdef"
	key256   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	otherKey = "abcdef0123456789abcdef0123456789"
)

func TestCipher_Encrypt(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		key           string
		plaintext     string
		wantErr       bool
		wantDifferent bool
	}{
		"encrypts plaintext": {
			key:       key128,
			plaintext: "test plaintext",
		},
		"encrypts with AES-256": {
			key:       key256,
			plaintext: "test plaintext",
		},
		"encrypts empty plaintext": {
			key:       key128,
			plaintext: "",
		},
		"uses random nonce": {
			key:           key128,
			plaintext:     "test plaintext",
			wantDifferent: true,
		},
		"rejects non-hexadecimal key": {
			key:       "not-hexadecimal",
			plaintext: "test plaintext",
			wantErr:   true,
		},
		"rejects invalid key length": {
			key:       "0123",
			plaintext: "test plaintext",
			wantErr:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cipher, err := security.NewCipher(tt.key)
			if err != nil {
				t.Fatalf("NewCipher() error = %v, want nil", err)
			}
			got, err := cipher.Encrypt(tt.plaintext)
			if tt.wantErr {
				if err == nil {
					t.Error("Encrypt() error = nil, want an error")
				}
				if got != "" {
					t.Errorf("Encrypt() = %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Encrypt() error = %v, want nil", err)
			}
			if got == "" {
				t.Fatal("Encrypt() returned empty ciphertext")
			}

			if tt.wantDifferent {
				other, err := cipher.Encrypt(tt.plaintext)
				if err != nil {
					t.Fatalf("second Encrypt() error = %v, want nil", err)
				}
				if got == other {
					t.Errorf("Encrypt() returned identical ciphertext %q", got)
				}
			}
		})
	}
}

func TestCipher_Decrypt(t *testing.T) {
	t.Parallel()

	cipher128, err := security.NewCipher(key128)
	if err != nil {
		t.Fatalf("prepare AES-128 cipher: NewCipher() error = %v", err)
	}
	encrypted128, err := cipher128.Encrypt("test plaintext")
	if err != nil {
		t.Fatalf("prepare AES-128 ciphertext: Encrypt() error = %v", err)
	}

	cipher256, err := security.NewCipher(key256)
	if err != nil {
		t.Fatalf("prepare AES-256 cipher: NewCipher() error = %v", err)
	}
	encrypted256, err := cipher256.Encrypt("test plaintext")
	if err != nil {
		t.Fatalf("prepare AES-256 ciphertext: Encrypt() error = %v", err)
	}

	cipher128Empty, err := security.NewCipher(key128)
	if err != nil {
		t.Fatalf("prepare AES-128 cipher: NewCipher() error = %v", err)
	}
	encryptedEmpty, err := cipher128Empty.Encrypt("")
	if err != nil {
		t.Fatalf("prepare empty ciphertext: Encrypt() error = %v", err)
	}

	replacement := "0"
	if encrypted128[len(encrypted128)-1:] == replacement {
		replacement = "1"
	}
	tampered := encrypted128[:len(encrypted128)-1] + replacement

	tests := map[string]struct {
		key           string
		encryptedText string
		want          string
		wantErr       bool
		wantExactErr  error
	}{
		"decrypts AES-128 ciphertext": {
			key:           key128,
			encryptedText: encrypted128,
			want:          "test plaintext",
		},
		"decrypts AES-256 ciphertext": {
			key:           key256,
			encryptedText: encrypted256,
			want:          "test plaintext",
		},
		"decrypts empty plaintext": {
			key:           key128,
			encryptedText: encryptedEmpty,
			want:          "",
		},
		"rejects malformed encrypted text": {
			key:           key128,
			encryptedText: "missing-separator",
			wantErr:       true,
		},
		"rejects short nonce": {
			key:           key128,
			encryptedText: "00:00",
			wantErr:       true,
			wantExactErr:  security.ErrInvalidNonceSize,
		},
		"rejects long nonce": {
			key:           key128,
			encryptedText: "00000000000000000000000000:00",
			wantErr:       true,
			wantExactErr:  security.ErrInvalidNonceSize,
		},
		"rejects wrong key": {
			key:           otherKey,
			encryptedText: encrypted128,
			wantErr:       true,
		},
		"rejects tampered ciphertext": {
			key:           key128,
			encryptedText: tampered,
			wantErr:       true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cipher, err := security.NewCipher(tt.key)
			if err != nil {
				t.Fatalf("NewCipher() error = %v, want nil", err)
			}
			got, err := cipher.Decrypt(tt.encryptedText)
			if tt.wantErr {
				if err == nil {
					t.Error("Decrypt() error = nil, want an error")
				}
				if tt.wantExactErr != nil && !errors.Is(err, tt.wantExactErr) {
					t.Errorf("Decrypt() error = %v, want %v", err, tt.wantExactErr)
				}
				if got != "" {
					t.Errorf("Decrypt() = %q, want empty", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decrypt() error = %v, want nil", err)
			}
			if got != tt.want {
				t.Errorf("Decrypt() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewCipher(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		want    *security.Cipher
		wantErr error
	}{
		{
			name:    "succesfull init",
			key:     key128,
			want:    &security.Cipher{SecretKey: key128},
			wantErr: nil,
		},
		{
			name:    "empty key",
			key:     "",
			wantErr: security.ErrCipherRequiredKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := security.NewCipher(tt.key)
			if !errors.Is(gotErr, tt.wantErr) {
				t.Errorf("NewCipher() failed: %v", gotErr)
				return
			}

			if !cmp.Equal(got, tt.want) {
				t.Errorf("NewCipher() failed got:%v want:%v", got, tt.want)
			}

		})
	}
}
