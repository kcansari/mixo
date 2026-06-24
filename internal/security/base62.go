package security

import (
	"errors"
	"math/big"
)

const encodeStd = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// ErrNilInput is returned by Encode when the input *big.Int is nil.
// ErrNegative is returned by Encode when the input is a negative number.
var (
	ErrNilInput = errors.New("base62: nil input")
	ErrNegative = errors.New("base62: negative number")
)

// Encode returns the base62 representation of num using the alphabet
// 0-9A-Za-z, or an error if num is nil or negative.
func Encode(num *big.Int) (string, error) {

	if num == nil {
		return "", ErrNilInput
	}

	if num.Sign() < 0 {
		return "", ErrNegative
	}

	value := new(big.Int).Set(num)
	base62 := big.NewInt(62)
	mod := new(big.Int)

	var digits []byte
	for {
		value.DivMod(value, base62, mod) // value=quotient, mod=remainder
		digits = append(digits, encodeStd[(mod.Int64())])
		if value.Sign() == 0 {
			break
		}
	}

	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits), nil
}
