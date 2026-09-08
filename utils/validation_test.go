package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidPasswordLengthBoundary(t *testing.T) {
	// "Aa1!" satisfies every character class, so length is the only variable.
	atLimit := strings.Repeat("Aa1!", 18) // 72 bytes

	testCases := []struct {
		name     string
		password string
		want     bool
	}{
		{"below the minimum", "Aa1!Aa1", false},
		{"at the minimum", "Aa1!Aa1!", true},
		{"at the maximum", atLimit, true},
		{"one byte over the maximum", atLimit + "a", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsValidPassword(tc.password))
		})
	}

	assert.Len(t, atLimit, maxPasswordLen, "the boundary fixture must be exactly at the limit")
}

// The limit is bcrypt's, which counts bytes. A password of multi-byte runes can
// be well under 72 characters and still be too long to hash.
func TestIsValidPasswordCountsBytesNotRunes(t *testing.T) {
	password := strings.Repeat("Aa1!", 17) + "ééé" // 71 runes, 74 bytes

	assert.Len(t, []rune(password), 71)
	assert.Greater(t, len(password), maxPasswordLen)
	assert.False(t, IsValidPassword(password))
}

func TestValidateRegistrationInputRejectsOverLongPassword(t *testing.T) {
	err := ValidateRegistrationInput("John", "Doe", "user@example.com", strings.Repeat("Aa1!", 19))

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid password format")
}
