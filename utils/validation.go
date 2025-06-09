package utils

import (
	"errors"
	"net/mail"
	"regexp"
	"strings"
)

// IsValidEmail validates email format using Go's net/mail package
// and additional checks for length and format compliance
func IsValidEmail(email string) bool {
	// Basic length check (RFC 5321 limits)
	if len(email) < 3 || len(email) > 254 {
		return false
	}

	// Trim whitespace
	email = strings.TrimSpace(email)

	// Use net/mail for parsing
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	// Additional checks - ensure parsed address matches original
	if addr.Address != email {
		return false
	}

	// Check for at least one dot in domain part
	parts := strings.Split(email, "@")
	if len(parts) != 2 || !strings.Contains(parts[1], ".") {
		return false
	}

	return true
}

// IsValidPassword validates password strength with comprehensive rules
func IsValidPassword(password string) bool {
	// Basic length check
	if len(password) < 8 || len(password) > 128 {
		return false
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	// Check each character
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
	}

	// All criteria must be met
	return hasUpper && hasLower && hasNumber && hasSpecial
}

// IsValidName validates first/last names
func IsValidName(name string) bool {
	if len(strings.TrimSpace(name)) < 1 || len(name) > 100 {
		return false
	}

	// Optional: Check for valid characters (letters, spaces, hyphens, apostrophes)
	validNameRegex := regexp.MustCompile(`^[a-zA-Z\s\-']+$`)
	return validNameRegex.MatchString(strings.TrimSpace(name))
}

// ValidateRegistrationInput validates all registration input fields
func ValidateRegistrationInput(firstName, lastName, email, password string) error {
	firstName = strings.TrimSpace(firstName)
	lastName = strings.TrimSpace(lastName)
	email = strings.TrimSpace(email)

	if firstName == "" || lastName == "" || email == "" || password == "" {
		return errors.New("all fields are required")
	}

	if !IsValidName(firstName) {
		return errors.New("invalid first name format")
	}

	if !IsValidName(lastName) {
		return errors.New("invalid last name format")
	}

	if !IsValidEmail(email) {
		return errors.New("invalid email format")
	}

	if !IsValidPassword(password) {
		return errors.New("invalid password format")
	}

	return nil
}
