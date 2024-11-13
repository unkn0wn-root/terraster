package service

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/unkn0wn-root/go-load-balancer/internal/auth/database"
	"github.com/unkn0wn-root/go-load-balancer/internal/auth/models"
	"github.com/unkn0wn-root/go-load-balancer/internal/auth/validation"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserLocked         = errors.New("account is temporarily locked")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrRevokedToken       = errors.New("token has been revoked")
	ErrMaxTokensReached   = errors.New("maximum number of active tokens reached")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUsernameTaken      = errors.New("username already exists")
	ErrPasswordExpired    = errors.New("password has expired")
)

type AuthConfig struct {
	JWTSecret            []byte
	TokenExpiry          time.Duration
	RefreshTokenExpiry   time.Duration
	MaxLoginAttempts     int
	LockDuration         time.Duration
	MaxActiveTokens      int
	PasswordMinLength    int
	RequireSpecialChar   bool
	RequireNumber        bool
	RequireUppercase     bool
	TokenCleanupInterval time.Duration
	PasswordExpiryDays   int // e.g., 90 days
	PasswordHistoryLimit int // Number of previous passwords to remember
}

type AuthService struct {
	db              *database.SQLiteDB
	config          AuthConfig
	done            chan struct{}
	passwordExpiry  time.Duration
	passwordHistory int
}

func NewAuthService(db *database.SQLiteDB, config AuthConfig) *AuthService {
	s := &AuthService{
		db:     db,
		config: config,
		done:   make(chan struct{}),
	}

	// Start token cleanup goroutine
	go s.tokenCleanupRoutine()

	return s
}

func (s *AuthService) GetConfig() AuthConfig {
	return s.config
}

func (s *AuthService) Close() {
	close(s.done)
}

func (s *AuthService) IsPasswordExpired(user *models.User) bool {
	return time.Since(user.PasswordChangedAt) > s.passwordExpiry
}

func (s *AuthService) validator() *validation.PasswordValidator {
	return validation.NewPasswordValidator(validation.PasswordPolicy{
		MinLength:           s.config.PasswordMinLength,
		MaxLength:           128,
		RequireUppercase:    s.config.RequireUppercase,
		RequireLowercase:    true,
		RequireNumbers:      s.config.RequireNumber,
		RequireSpecial:      s.config.RequireSpecialChar,
		MaxRepeatingChars:   3,
		PreventSequential:   true,
		PreventUsernamePart: true,
	})
}

func (s *AuthService) tokenCleanupRoutine() {
	ticker := time.NewTicker(s.config.TokenCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.db.CleanupExpiredTokens(); err != nil {
				// You might want to use a proper logger here
				println("Error cleaning up tokens:", err.Error())
			}
		case <-s.done:
			return
		}
	}
}

func (s *AuthService) ValidatePasswordHistory(newPassword string, previousPasswords []string) error {
	// Check if the new password matches any of the previous passwords
	for _, prevHash := range previousPasswords {
		if err := bcrypt.CompareHashAndPassword([]byte(prevHash), []byte(newPassword)); err == nil {
			return errors.New("password has been used recently")
		}
	}
	return nil
}

func (s *AuthService) ChangePassword(userID int64, oldPassword, newPassword string) error {
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return errors.New("current password is incorrect")
	}

	// Validate new password using our existing password validator
	validator := s.validator()
	if err := validator.ValidatePassword(newPassword, user.Username); err != nil {
		return fmt.Errorf("invalid new password: %w", err)
	}

	previousPasswords := user.GetPreviousPasswords()

	if err := s.ValidatePasswordHistory(newPassword, previousPasswords); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password history
	previousPasswords = append(previousPasswords, user.Password)
	if len(previousPasswords) > s.passwordHistory {
		previousPasswords = previousPasswords[len(previousPasswords)-s.passwordHistory:]
	}

	passwordHistoryJSON, err := json.Marshal(previousPasswords)
	if err != nil {
		return err
	}

	// Update user
	now := time.Now()
	user.Password = string(hashedPassword)
	user.PasswordChangedAt = now
	user.UpdatedAt = now
	user.PreviousPasswords = string(passwordHistoryJSON)

	// Revoke all existing tokens
	if err := s.db.RevokeAllUserTokens(userID); err != nil {
		return err
	}

	return s.db.UpdateUserPassword(user)
}

func (s *AuthService) CreateUser(username, password string, role models.Role) error {
	existing, err := s.db.GetUserByUsername(username)
	if err == nil && existing != nil {
		return ErrUsernameTaken
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("error checking username: %w", err)
	}

	// Validate password
	validator := s.validator()
	if err := validator.ValidatePassword(password, username); err != nil {
		return fmt.Errorf("invalid password: %w", err)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user := &models.User{
		Username:  username,
		Password:  string(hashedPassword),
		Role:      role,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	return s.db.CreateUser(user)
}

func (s *AuthService) AuthenticateUser(username, password string, r *http.Request) (*models.Token, error) {
	user, err := s.db.GetUserByUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, ErrUserLocked
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		user.FailedAttempts++
		if user.FailedAttempts >= s.config.MaxLoginAttempts {
			lockUntil := time.Now().Add(s.config.LockDuration)
			user.LockedUntil = &lockUntil
		}
		s.db.UpdateUser(user)
		return nil, ErrInvalidCredentials
	}

	// Check if password is expired
	if s.IsPasswordExpired(user) {
		return nil, ErrPasswordExpired
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		// Increment failed attempts
		user.FailedAttempts++
		if user.FailedAttempts >= s.config.MaxLoginAttempts {
			lockUntil := time.Now().Add(s.config.LockDuration)
			user.LockedUntil = &lockUntil
		}
		s.db.UpdateUser(user)
		return nil, ErrInvalidCredentials
	}

	// Reset failed attempts on successful login
	user.FailedAttempts = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = r.RemoteAddr
	s.db.UpdateUser(user)

	// Generate token
	token, err := s.generateToken(user, r)
	if err != nil {
		return nil, err
	}

	// Log successful login
	s.logAudit(user.ID, "login", "auth", "success", r, nil)

	return token, nil
}

func (s *AuthService) generateToken(user *models.User, r *http.Request) (*models.Token, error) {
	// Check active tokens count
	activeTokens, err := s.db.CountActiveTokens(user.ID)
	if err != nil {
		return nil, err
	}

	if activeTokens >= s.config.MaxActiveTokens {
		return nil, ErrMaxTokensReached
	}

	// Generate JWT ID
	jwtID, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(s.config.TokenExpiry).Unix(),
		"jti":     jwtID,
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.config.JWTSecret)
	if err != nil {
		return nil, err
	}

	// Create token record
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

func (s *AuthService) RefreshToken(refreshToken string, r *http.Request) (*models.Token, error) {
	claims, err := s.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, ErrInvalidToken
	}

	oldToken, err := s.db.GetTokenByRefreshToken(refreshToken, int64(userID))
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Check if refresh token is expired or revoked
	if oldToken.RevokedAt != nil {
		return nil, ErrRevokedToken
	}

	// Get user
	user, err := s.db.GetUserByID(oldToken.UserID)
	if err != nil {
		return nil, err
	}

	// Generate new token
	newToken, err := s.generateToken(user, r)
	if err != nil {
		return nil, err
	}

	// Revoke old token
	now := time.Now()
	oldToken.RevokedAt = &now
	if err := s.db.UpdateToken(oldToken); err != nil {
		return nil, err
	}

	// Save new token
	if err := s.db.CreateToken(newToken); err != nil {
		return nil, err
	}

	return newToken, nil
}

func (s *AuthService) ValidateToken(tokenString string) (*jwt.MapClaims, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("invalid signing method")
		}
		return s.config.JWTSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Get JTI claim
	jti, ok := claims["jti"].(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	// Validate token in database
	dbToken, err := s.db.GetTokenByJTI(jti)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if dbToken.RevokedAt != nil {
		return nil, ErrRevokedToken
	}

	// Update last used time
	dbToken.LastUsedAt = time.Now()
	s.db.UpdateToken(dbToken)

	return &claims, nil
}

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

func (s *AuthService) RevokeToken(tokenString string) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return s.config.JWTSecret, nil
	})
	if err != nil {
		return err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return ErrInvalidToken
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		return ErrInvalidToken
	}

	dbToken, err := s.db.GetTokenByJTI(jti)
	if err != nil {
		return err
	}

	now := time.Now()
	dbToken.RevokedAt = &now
	return s.db.UpdateToken(dbToken)
}

func (s *AuthService) GetActiveSessions(userID int64) ([]models.Session, error) {
	return s.db.GetUserSessions(userID)
}

func (s *AuthService) logAudit(userID int64, action, resource, status string, r *http.Request, details interface{}) {
	detailsJSON, _ := json.Marshal(details)

	log := &models.AuditLog{
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Status:    status,
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Details:   string(detailsJSON),
		CreatedAt: time.Now(),
	}

	// Using go routine to not block the main flow
	go func() {
		if err := s.db.CreateAuditLog(log); err != nil {
			println("Error creating audit log:", err.Error())
		}
	}()
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
