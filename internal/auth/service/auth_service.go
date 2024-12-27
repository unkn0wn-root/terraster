package service

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	apierr "github.com/unkn0wn-root/terraster/internal/auth"
	"github.com/unkn0wn-root/terraster/internal/auth/database"
	"github.com/unkn0wn-root/terraster/internal/auth/models"
	"github.com/unkn0wn-root/terraster/internal/auth/validation"
	"golang.org/x/crypto/bcrypt"
)

// AuthConfig holds the configuration settings for the authentication service.
// JWT settings, token expiration durations, password policies, and more.
type AuthConfig struct {
	JWTSecret            []byte        // Secret key used for signing JWT tokens.
	TokenExpiry          time.Duration // Duration after which access tokens expire.
	RefreshTokenExpiry   time.Duration // Duration after which refresh tokens expire.
	MaxLoginAttempts     int           // Maximum number of failed login attempts before locking the account.
	LockDuration         time.Duration // Duration for which the account is locked after exceeding login attempts.
	MaxActiveTokens      int           // Maximum number of active tokens a user can have simultaneously.
	PasswordMinLength    int           // Minimum required length for user passwords.
	RequireSpecialChar   bool          // Whether passwords must include at least one special character.
	RequireNumber        bool          // Whether passwords must include at least one numeric character.
	RequireUppercase     bool          // Whether passwords must include at least one uppercase letter.
	TokenCleanupInterval time.Duration // Interval at which expired tokens are cleaned up from the database.
	PasswordExpiryDays   int           // Number of days after which passwords expire.
	PasswordHistoryLimit int           // Number of previous passwords to retain and prevent reuse.
}

// AuthService manages user authentication, token generation, password policies, and related functionalities.
type AuthService struct {
	db              *database.SQLiteDB // Database interface for authentication-related operations.
	config          AuthConfig         // Configuration settings for the authentication service.
	done            chan struct{}      // Channel used to signal the termination of background goroutines.
	passwordExpiry  time.Duration      // Duration after which a user's password is considered expired.
	passwordHistory int                // Number of previous passwords to track for preventing reuse.
}

// NewAuthService initializes and returns a new instance of AuthService.
// Sets up the authentication service with the provided database and configuration,
// and starts a background routine for cleaning up expired tokens.
func NewAuthService(db *database.SQLiteDB, config AuthConfig) *AuthService {
	if config.PasswordExpiryDays == 0 {
		config.PasswordExpiryDays = 1
	}

	if config.PasswordHistoryLimit == 0 {
		config.PasswordHistoryLimit = 5
	}

	s := &AuthService{
		db:              db,
		config:          config,
		done:            make(chan struct{}),
		passwordExpiry:  time.Duration(config.PasswordExpiryDays) * 24 * time.Hour,
		passwordHistory: config.PasswordHistoryLimit,
	}

	// Start token cleanup goroutine to periodically remove expired tokens.
	go s.tokenCleanupRoutine()

	return s
}

func (s *AuthService) GetConfig() AuthConfig {
	return s.config
}

func (s *AuthService) Close() {
	close(s.done)
}

// IsPasswordExpired checks whether a user's password has expired based on the PasswordChangedAt timestamp.
// Returns true if the password is older than the configured passwordExpiry duration.
func (s *AuthService) IsPasswordExpired(user *models.User) bool {
	fmt.Println("Password Changed At: ", user.PasswordChangedAt)
	fmt.Println("Password Expiry: ", s.passwordExpiry)
	return time.Since(user.PasswordChangedAt) > s.passwordExpiry
}

// validator creates and returns a new PasswordValidator based on the current password policies.
// Enforces rules such as minimum length, character requirements, and other password strength criteria.
func (s *AuthService) validator() *validation.PasswordValidator {
	return validation.NewPasswordValidator(validation.PasswordPolicy{
		MinLength:           s.config.PasswordMinLength,  // Minimum length requirement for passwords.
		MaxLength:           128,                         // Maximum length allowed for passwords.
		RequireUppercase:    s.config.RequireUppercase,   // Enforce at least one uppercase letter.
		RequireLowercase:    true,                        // Enforce at least one lowercase letter.
		RequireNumbers:      s.config.RequireNumber,      // Enforce at least one numeric character.
		RequireSpecial:      s.config.RequireSpecialChar, // Enforce at least one special character.
		MaxRepeatingChars:   3,                           // Maximum number of repeating characters allowed.
		PreventSequential:   true,                        // Prevent sequential characters in passwords.
		PreventUsernamePart: true,                        // Prevent inclusion of parts of the username in the password.
	})
}

// tokenCleanupRoutine runs periodically to clean up expired tokens from the database.
func (s *AuthService) tokenCleanupRoutine() {
	ticker := time.NewTicker(s.config.TokenCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.db.CleanupExpiredTokens(); err != nil {
				println("Error cleaning up tokens:", err.Error()) // @toDo - use proper logging here
			}
		case <-s.done:
			return
		}
	}
}

// ValidatePasswordHistory checks whether the new password has been used recently by the user.
// Compare the new password against a list of previous password hashes to prevent reuse.
func (s *AuthService) ValidatePasswordHistory(newPassword string, previousPasswords []string) error {
	// Iterate through each previous password hash.
	for _, prevHash := range previousPasswords {
		if err := bcrypt.CompareHashAndPassword([]byte(prevHash), []byte(newPassword)); err == nil {
			return errors.New("password has been used recently")
		}
	}

	return nil
}

// ChangePassword allows a user to update their password.
// It verifies the old password, validates the new password against policies,
// checks password history, hashes the new password, updates the user's record,
// and revokes all existing tokens to enforce the password change.
func (s *AuthService) ChangePassword(userID int64, oldPassword, newPassword string) error {
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return apierr.ErrInvalidCredentials
	}

	validator := s.validator()
	if err := validator.ValidatePassword(newPassword, user.Username); err != nil {
		return fmt.Errorf("invalid new password: %w", err)
	}

	previousPasswords := user.GetPreviousPasswords()
	if err := s.ValidatePasswordHistory(newPassword, previousPasswords); err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	previousPasswords = append(previousPasswords, user.Password)
	if len(previousPasswords) > s.passwordHistory {
		previousPasswords = previousPasswords[len(previousPasswords)-s.passwordHistory:]
	}

	passwordHistoryJSON, err := json.Marshal(previousPasswords)
	if err != nil {
		return err
	}

	now := time.Now()
	user.Password = string(hashedPassword)
	user.PasswordChangedAt = now
	user.UpdatedAt = now
	user.PreviousPasswords = string(passwordHistoryJSON)

	// Revoke all existing tokens associated with the user to enforce the password change.
	if err := s.db.RevokeAllUserTokens(userID); err != nil {
		return err
	}

	return s.db.UpdateUserPassword(user)
}

// CreateUser registers a new user with the provided username, password, and role.
// Check for username uniqueness, validates the password, hashes it, and stores the user in the database.
func (s *AuthService) CreateUser(username, password string, role models.Role) error {
	existing, err := s.db.GetUserByUsername(username)
	if err == nil && existing != nil {
		return apierr.ErrUsernameTaken
	}

	if err != nil && !errors.Is(err, apierr.ErrUserNotFound) {
		return fmt.Errorf("error checking username: %w", err)
	}

	validator := s.validator()
	if err := validator.ValidatePassword(password, username); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &models.User{
		Username:          username,
		Password:          string(hashedPassword),
		Role:              role,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
		PasswordChangedAt: time.Now(),
	}

	return s.db.CreateUser(user)
}

// AuthenticateUser authenticates a user with the provided username and password.
// Verifies credentials, checks account lock status and password expiry,
// generates a new token upon successful authentication, and logs the login event.
func (s *AuthService) AuthenticateUser(username, password string, r *http.Request) (*models.Token, error) {
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		return nil, apierr.ErrInvalidCredentials
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, apierr.ErrUserLocked
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		user.FailedAttempts++
		// Lock the account if the maximum number of failed attempts is reached.
		if user.FailedAttempts >= s.config.MaxLoginAttempts {
			lockUntil := time.Now().Add(s.config.LockDuration)
			user.LockedUntil = &lockUntil
		}

		s.db.UpdateUser(user)
		return nil, apierr.ErrInvalidCredentials
	}

	if s.IsPasswordExpired(user) {
		return nil, apierr.ErrPasswordExpired
	}

	user.FailedAttempts = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = r.RemoteAddr

	s.db.UpdateUser(user)

	token, err := s.generateToken(user, r)
	if err != nil {
		return nil, err
	}

	s.logAudit(user.ID, "login", "auth", "success", r, nil)

	return token, nil
}

// generateToken creates a new JWT token for the specified user and request context.
// It ensures that the user has not exceeded the maximum number of active tokens,
// generates unique identifiers for the token, signs it, and stores it in the database.
func (s *AuthService) generateToken(user *models.User, r *http.Request) (*models.Token, error) {
	activeTokens, err := s.db.CountActiveTokens(user.ID)
	if err != nil {
		return nil, err
	}

	if activeTokens >= s.config.MaxActiveTokens {
		return nil, apierr.ErrMaxTokensReached
	}

	jwtID, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(s.config.TokenExpiry).Unix(),
		"jti":     jwtID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.config.JWTSecret)
	if err != nil {
		return nil, err
	}

	tokenRecord := &models.Token{
		UserID:       user.ID,
		Token:        tokenString,
		RefreshToken: refreshToken,
		JTI:          jwtID,
		Role:         user.Role,
		ExpiresAt:    time.Now().Add(s.config.TokenExpiry),
		CreatedAt:    time.Now(),
		LastUsedAt:   time.Now(),
		ClientIP:     r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}

	if err := s.db.CreateToken(tokenRecord); err != nil {
		return nil, err
	}

	return tokenRecord, nil
}

// RefreshToken generates a new access token using a valid refresh token.
// It validates the refresh token, revokes the old token, generates a new one, and stores it in the database.
func (s *AuthService) RefreshToken(refreshToken string, r *http.Request) (*models.Token, error) {
	claims, err := s.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, apierr.ErrInvalidToken
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, apierr.ErrInvalidToken
	}

	oldToken, err := s.db.GetTokenByRefreshToken(refreshToken, int64(userID))
	if err != nil {
		return nil, apierr.ErrInvalidToken
	}

	if oldToken.RevokedAt != nil {
		return nil, apierr.ErrRevokedToken
	}

	user, err := s.db.GetUserByID(oldToken.UserID)
	if err != nil {
		return nil, err
	}

	newToken, err := s.generateToken(user, r)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	oldToken.RevokedAt = &now
	if err := s.db.UpdateToken(oldToken); err != nil {
		return nil, err
	}

	if err := s.db.CreateToken(newToken); err != nil {
		return nil, err
	}

	return newToken, nil
}

// ValidateToken verifies the validity of a JWT token.
// It checks the token's signature, expiration, and revocation status.
func (s *AuthService) ValidateToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return s.config.JWTSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, apierr.ErrInvalidToken
	}

	// Extract the claims from the token.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, apierr.ErrInvalidToken
	}

	// Retrieve the JWT ID (JTI) from the claims.
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, apierr.ErrInvalidToken
	}

	dbToken, err := s.db.GetTokenByJTI(jti)
	if err != nil {
		return nil, apierr.ErrInvalidToken
	}

	if dbToken.RevokedAt != nil {
		return nil, apierr.ErrRevokedToken
	}

	dbToken.LastUsedAt = time.Now()
	s.db.UpdateToken(dbToken)

	return &claims, nil
}

// validateRefreshToken parses and validates a refresh token.
// Ensures the token is correctly signed and extracts the claims for further validation.
func (s *AuthService) validateRefreshToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.config.JWTSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RevokeToken revokes a specific JWT token by its token string.
// Marks the token as revoked in the database to prevent further use.
func (s *AuthService) RevokeToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.config.JWTSecret, nil
	})
	if err != nil {
		return err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return apierr.ErrInvalidToken
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return apierr.ErrInvalidToken
	}

	dbToken, err := s.db.GetTokenByJTI(jti)
	if err != nil {
		return err
	}

	now := time.Now()
	dbToken.RevokedAt = &now

	return s.db.UpdateToken(dbToken)
}

// GetActiveSessions retrieves all active sessions (tokens) for a given user.
// Allows users or administrators to view currently active authentication sessions.
func (s *AuthService) GetActiveSessions(userID int64) ([]models.Session, error) {
	return s.db.GetUserSessions(userID)
}

func (s *AuthService) GetUserById(userID int64) (*models.User, error) {
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// logAudit records an audit log entry for a specific action performed by a user.
// It captures details such as the user ID, action type, resource affected, status,
// client IP, user agent, and any additional details provided.
func (s *AuthService) logAudit(userID int64, action, resource, status string, r *http.Request, details interface{}) {
	detailsJSON, _ := json.Marshal(details)

	log := &models.AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Status:    status,
		IP:        r.RemoteAddr,        // Capture the client's IP address.
		UserAgent: r.UserAgent(),       // Capture the client's User-Agent string.
		Details:   string(detailsJSON), // Include any additional details in JSON format.
		CreatedAt: time.Now(),          // Timestamp of the audit log entry.
	}

	go func() {
		if err := s.db.CreateAuditLog(log); err != nil {
			println("Error creating audit log:", err.Error())
		}
	}()
}

// generateRandomString creates a secure random string of the specified length.
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
