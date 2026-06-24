package security

import (
	"errors"
	"math/big"
	"testing"
)

func TestEncode(t *testing.T) {
	tests := map[string]struct {
		input   *big.Int
		result  string
		wantErr error
	}{
		"normal value": {
			input:   big.NewInt(12345),
			result:  "3D7",
			wantErr: nil,
		},
		"negative number": {
			input:   big.NewInt(-3),
			result:  "",
			wantErr: ErrNegative,
		},
		"nil input": {
			input:   nil,
			result:  "",
			wantErr: ErrNilInput,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := Encode(test.input)
			if !errors.Is(err, test.wantErr) {
				t.Errorf("Encode(%d) error %v; wantErr %v", test.input, err, test.wantErr)
			}

			if got != test.result {
				t.Errorf("Encode(%d) = %q; want %q", test.input, got, test.result)
			}
		})
	}
}
