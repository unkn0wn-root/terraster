package apierr

import "errors"

var (
	// ErrUserLocked is returned when a user's account is temporarily locked due to excessive failed login attempts.
	ErrUserLocked = errors.New("account is temporarily locked")
	// ErrInvalidToken is returned when a provided token is invalid or has expired.
	ErrInvalidToken = errors.New("invalid or expired token")
	// ErrRevokedToken is returned when a token has been explicitly revoked.
	ErrRevokedToken = errors.New("token has been revoked")
	// ErrMaxTokensReached is returned when a user has reached the maximum number of active tokens allowed.
	ErrMaxTokensReached = errors.New("maximum number of active tokens reached")
	// ErrInvalidCredentials is returned when a user provides incorrect authentication credentials.
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUsernameTaken is returned when attempting to create a user with a username that already exists.
	ErrUsernameTaken = errors.New("username already exists")
	// ErrPasswordExpired is returned when a user's password has expired and needs to be changed.
	ErrPasswordExpired = errors.New("password has expired")
	// ErrUserNotFound is returned when a user record is not found in the database.
	ErrUserNotFound = errors.New("user not found")
)
