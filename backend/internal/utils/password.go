// Package utils provides password validation for ModernAuth.
package utils

import (
	"errors"
	"strings"
	"unicode"
)

// PasswordPolicy defines the password requirements.
type PasswordPolicy struct {
	MinLength        int  `json:"min_length"`
	MaxLength        int  `json:"max_length"`
	RequireUppercase bool `json:"require_uppercase"`
	RequireLowercase bool `json:"require_lowercase"`
	RequireDigit     bool `json:"require_digit"`
	RequireSpecial   bool `json:"require_special"`
}

// DefaultPasswordPolicy returns the default password policy.
func DefaultPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   false,
	}
}

// StrictPasswordPolicy returns a stricter password policy.
func StrictPasswordPolicy() *PasswordPolicy {
	return &PasswordPolicy{
		MinLength:        12,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}
}

// PasswordValidationError contains details about password validation failure.
type PasswordValidationError struct {
	Errors []string
}

func (e *PasswordValidationError) Error() string {
	return "password validation failed: " + strings.Join(e.Errors, ", ")
}

// Common weak passwords that should be rejected.
var commonPasswords = map[string]bool{
	"password":    true,
	"password1":   true,
	"password123": true,
	"123456":      true,
	"12345678":    true,
	"123456789":   true,
	"1234567890":  true,
	"qwerty":      true,
	"qwerty123":   true,
	"abc123":      true,
	"monkey":      true,
	"master":      true,
	"dragon":      true,
	"111111":      true,
	"baseball":    true,
	"iloveyou":    true,
	"trustno1":    true,
	"sunshine":    true,
	"princess":    true,
	"welcome":     true,
	"shadow":      true,
	"superman":    true,
	"michael":     true,
	"football":    true,
	"letmein":     true,
	"admin":       true,
	"admin123":    true,
	"root":        true,
	"toor":        true,
	"pass":        true,
	"test":        true,
	"guest":       true,
	"changeme":    true,
	"default":     true,
}

// ValidatePassword validates a password against the given policy.
func ValidatePassword(password string, policy *PasswordPolicy) error {
	if policy == nil {
		policy = DefaultPasswordPolicy()
	}

	var errs []string

	// Check length
	if len(password) < policy.MinLength {
		errs = append(errs, "password must be at least "+itoa(policy.MinLength)+" characters")
	}
	if len(password) > policy.MaxLength {
		errs = append(errs, "password must be at most "+itoa(policy.MaxLength)+" characters")
	}

	// Check for common passwords
	if commonPasswords[strings.ToLower(password)] {
		errs = append(errs, "password is too common")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		errs = append(errs, "password must contain at least one uppercase letter")
	}
	if policy.RequireLowercase && !hasLower {
		errs = append(errs, "password must contain at least one lowercase letter")
	}
	if policy.RequireDigit && !hasDigit {
		errs = append(errs, "password must contain at least one digit")
	}
	if policy.RequireSpecial && !hasSpecial {
		errs = append(errs, "password must contain at least one special character")
	}

	// Check for repeated characters (e.g., "aaaa" or "1111")
	if hasRepeatedChars(password, 4) {
		errs = append(errs, "password contains too many repeated characters")
	}

	// Check for sequential characters (e.g., "1234" or "abcd")
	if hasSequentialChars(password, 4) {
		errs = append(errs, "password contains sequential characters")
	}

	if len(errs) > 0 {
		return &PasswordValidationError{Errors: errs}
	}

	return nil
}

// ValidatePasswordWithContext validates a password and checks if it contains user data.
func ValidatePasswordWithContext(password string, policy *PasswordPolicy, email, username string) error {
	// First run standard validation
	if err := ValidatePassword(password, policy); err != nil {
		var pve *PasswordValidationError
		if errors.As(err, &pve) {
			// Add context-specific checks
			errs := pve.Errors

			lowPassword := strings.ToLower(password)

			// Check if password contains email
			if email != "" {
				emailLocal := strings.Split(strings.ToLower(email), "@")[0]
				if len(emailLocal) >= 3 && strings.Contains(lowPassword, emailLocal) {
					errs = append(errs, "password cannot contain your email address")
				}
			}

			// Check if password contains username
			if username != "" && len(username) >= 3 {
				if strings.Contains(lowPassword, strings.ToLower(username)) {
					errs = append(errs, "password cannot contain your username")
				}
			}

			if len(errs) > 0 {
				return &PasswordValidationError{Errors: errs}
			}
		}
		return err
	}

	// Run context-specific checks even if standard validation passed
	var errs []string
	lowPassword := strings.ToLower(password)

	if email != "" {
		emailLocal := strings.Split(strings.ToLower(email), "@")[0]
		if len(emailLocal) >= 3 && strings.Contains(lowPassword, emailLocal) {
			errs = append(errs, "password cannot contain your email address")
		}
	}

	if username != "" && len(username) >= 3 {
		if strings.Contains(lowPassword, strings.ToLower(username)) {
			errs = append(errs, "password cannot contain your username")
		}
	}

	if len(errs) > 0 {
		return &PasswordValidationError{Errors: errs}
	}

	return nil
}

// CalculatePasswordStrength returns a score from 0-100 indicating password strength.
func CalculatePasswordStrength(password string) int {
	score := 0

	length := len(password)
	if length >= 8 {
		score += 20
	}
	if length >= 12 {
		score += 10
	}
	if length >= 16 {
		score += 10
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if hasUpper {
		score += 15
	}
	if hasLower {
		score += 10
	}
	if hasDigit {
		score += 15
	}
	if hasSpecial {
		score += 20
	}

	// Penalize common patterns
	if commonPasswords[strings.ToLower(password)] {
		score -= 50
	}
	if hasRepeatedChars(password, 3) {
		score -= 10
	}
	if hasSequentialChars(password, 3) {
		score -= 10
	}

	// Ensure score is within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// GetPasswordStrengthLabel returns a human-readable label for the password strength.
func GetPasswordStrengthLabel(score int) string {
	switch {
	case score >= 80:
		return "strong"
	case score >= 60:
		return "good"
	case score >= 40:
		return "fair"
	case score >= 20:
		return "weak"
	default:
		return "very_weak"
	}
}

// hasRepeatedChars checks if the string has n or more repeated consecutive characters.
func hasRepeatedChars(s string, n int) bool {
	if len(s) < n {
		return false
	}

	count := 1
	prev := rune(0)
	for _, char := range s {
		if char == prev {
			count++
			if count >= n {
				return true
			}
		} else {
			count = 1
		}
		prev = char
	}
	return false
}

// hasSequentialChars checks if the string has n or more sequential characters.
func hasSequentialChars(s string, n int) bool {
	if len(s) < n {
		return false
	}

	runes := []rune(strings.ToLower(s))
	ascCount := 1
	descCount := 1

	for i := 1; i < len(runes); i++ {
		diff := int(runes[i]) - int(runes[i-1])

		if diff == 1 {
			ascCount++
			descCount = 1
			if ascCount >= n {
				return true
			}
		} else if diff == -1 {
			descCount++
			ascCount = 1
			if descCount >= n {
				return true
			}
		} else {
			ascCount = 1
			descCount = 1
		}
	}

	return false
}

// itoa converts an int to a string (simple implementation to avoid strconv import).
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	negative := i < 0
	if negative {
		i = -i
	}

	var result []byte
	for i > 0 {
		result = append([]byte{byte('0' + i%10)}, result...)
		i /= 10
	}

	if negative {
		result = append([]byte{'-'}, result...)
	}

	return string(result)
}
