// auth/validation/password.go
package validation

import (
	"errors"
	"strings"
	"unicode"
)

var (
	ErrPasswordTooShort = errors.New("password is too short")
	ErrPasswordTooLong  = errors.New("password is too long")
	ErrMissingUppercase = errors.New("password must contain at least one uppercase letter")
	ErrMissingLowercase = errors.New("password must contain at least one lowercase letter")
	ErrMissingNumber    = errors.New("password must contain at least one number")
	ErrMissingSpecial   = errors.New("password must contain at least one special character")
	ErrContainsUsername = errors.New("password cannot contain the username")
	ErrCommonPassword   = errors.New("password is too common")
	ErrConsecutiveChars = errors.New("password contains consecutive repeated characters")
	ErrSequentialChars  = errors.New("password contains sequential characters")
)

type PasswordPolicy struct {
	MinLength           int
	MaxLength           int
	RequireUppercase    bool
	RequireLowercase    bool
	RequireNumbers      bool
	RequireSpecial      bool
	MaxRepeatingChars   int
	PreventSequential   bool
	PreventUsernamePart bool
}

// DefaultPasswordPolicy returns a recommended password policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:           12,
		MaxLength:           128,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecial:      true,
		MaxRepeatingChars:   3,
		PreventSequential:   true,
		PreventUsernamePart: true,
	}
}

type PasswordValidator struct {
	policy PasswordPolicy
}

func NewPasswordValidator(policy PasswordPolicy) *PasswordValidator {
	return &PasswordValidator{
		policy: policy,
	}
}

func (v *PasswordValidator) ValidatePassword(password string, username string) error {
	// Check length
	if len(password) < v.policy.MinLength {
		return ErrPasswordTooShort
	}
	if len(password) > v.policy.MaxLength {
		return ErrPasswordTooLong
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	// Check character requirements
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if v.policy.RequireUppercase && !hasUpper {
		return ErrMissingUppercase
	}
	if v.policy.RequireLowercase && !hasLower {
		return ErrMissingLowercase
	}
	if v.policy.RequireNumbers && !hasNumber {
		return ErrMissingNumber
	}
	if v.policy.RequireSpecial && !hasSpecial {
		return ErrMissingSpecial
	}

	// Check for repeating characters
	if v.policy.MaxRepeatingChars > 0 {
		if err := v.checkRepeatingChars(password); err != nil {
			return err
		}
	}

	// Check for sequential characters
	if v.policy.PreventSequential {
		if err := v.checkSequentialChars(password); err != nil {
			return err
		}
	}

	// Check for username in password
	if v.policy.PreventUsernamePart && username != "" {
		if err := v.checkUsernameInPassword(password, username); err != nil {
			return err
		}
	}

	// Check against common passwords
	if err := v.checkCommonPasswords(password); err != nil {
		return err
	}

	return nil
}

func (v *PasswordValidator) checkRepeatingChars(password string) error {
	var count int
	var lastChar rune

	for i, char := range password {
		if i == 0 {
			lastChar = char
			count = 1
			continue
		}

		if char == lastChar {
			count++
			if count > v.policy.MaxRepeatingChars {
				return ErrConsecutiveChars
			}
		} else {
			lastChar = char
			count = 1
		}
	}
	return nil
}

func (v *PasswordValidator) checkSequentialChars(password string) error {
	sequences := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
	}

	lowPass := strings.ToLower(password)
	for _, seq := range sequences {
		for i := 0; i < len(seq)-2; i++ {
			if strings.Contains(lowPass, seq[i:i+3]) {
				return ErrSequentialChars
			}
			// Check reverse sequences too
			if strings.Contains(lowPass, reverse(seq[i:i+3])) {
				return ErrSequentialChars
			}
		}
	}
	return nil
}

func (v *PasswordValidator) checkUsernameInPassword(password, username string) error {
	if len(username) < 3 {
		return nil
	}

	lowPass := strings.ToLower(password)
	lowUser := strings.ToLower(username)

	if strings.Contains(lowPass, lowUser) {
		return ErrContainsUsername
	}

	return nil
}

func (v *PasswordValidator) checkCommonPasswords(password string) error {
	// This is a very small subset of common passwords
	// In a real implementation, you'd want to use a more comprehensive list
	commonPasswords := map[string]bool{
		"password123": true,
		"12345678":    true,
		"qwerty123":   true,
		"admin123":    true,
		"letmein":     true,
		"welcome1":    true,
	}

	if commonPasswords[strings.ToLower(password)] {
		return ErrCommonPassword
	}

	return nil
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
