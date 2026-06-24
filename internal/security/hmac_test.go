package security_test

import (
	"testing"

	"github.com/kcansari/mixo/internal/security"
)

func TestHmac_Sign(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		secret      string
		data        string
		otherSecret string
		otherData   string
		wantEqual   bool
	}{
		"same secret and data": {
			secret:    "secret",
			data:      "test",
			wantEqual: true,
		},
		"different secret and data": {
			secret:      "secret",
			data:        "test",
			otherSecret: "secret2",
			otherData:   "test2",
			wantEqual:   false,
		},
		"different data and same secret": {
			secret:    "secret",
			data:      "test",
			otherData: "test2",
			wantEqual: false,
		},
		"same data and different secret": {
			secret:      "secret",
			otherSecret: "secret2",
			data:        "test",
			otherData:   "test",
			wantEqual:   false,
		},
		"empty secret": {
			secret:    "",
			data:      "test",
			wantEqual: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			otherSecret := tt.otherSecret
			if otherSecret == "" {
				otherSecret = tt.secret
			}
			otherData := tt.otherData
			if otherData == "" {
				otherData = tt.data
			}

			got := security.NewHmac(tt.secret).Sign(tt.data)
			other := security.NewHmac(otherSecret).Sign(otherData)

			if equal := got == other; equal != tt.wantEqual {
				t.Errorf("Sign() equality = %t, want %t", equal, tt.wantEqual)
			}
		})
	}
}
