package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "modernc.org/sqlite"

	"github.com/unkn0wn-root/terraster/internal/auth/models"
)

// Schema for SQLite database defining the tables for users, tokens, and audit logs
// Includes foreign key constraints, default values, and indexing for optimized queries
const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,       -- Username must be unique.
    password TEXT NOT NULL,              -- Stores hashed passwords.
    role TEXT NOT NULL,                  -- Role of the user (e.g., admin, user).
    last_login_at DATETIME,              -- Tracks the last login timestamp.
    last_login_ip TEXT,                  -- IP address of the last login.
    failed_attempts INTEGER DEFAULT 0,   -- Tracks failed login attempts.
    locked_until DATETIME,               -- If set, user is locked until this time.
    created_at DATETIME NOT NULL,        -- User creation timestamp.
    updated_at DATETIME NOT NULL,        -- Timestamp for the last update.
    password_changed_at DATETIME,        -- Tracks last password change time.
    previous_passwords TEXT              -- JSON array of hashed previous passwords.
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,                -- References the user owning the token.
    token TEXT UNIQUE NOT NULL,              -- JWT or similar token.
    refresh_token_expires_at DATETIME,       -- Expiration timestamp of the refresh token.
    jti TEXT UNIQUE NOT NULL,                -- Unique token identifier.
    expires_at DATETIME NOT NULL,            -- Expiration timestamp of the token.
    created_at DATETIME NOT NULL,            -- Token creation time.
    last_used_at DATETIME NOT NULL,          -- Timestamp when the token was last used.
    revoked_at DATETIME,                     -- Timestamp if the token was revoked.
    client_ip TEXT NOT NULL,                 -- IP address associated with the token.
    user_agent TEXT NOT NULL,                -- User agent string.
    FOREIGN KEY (user_id) REFERENCES users (id) -- Foreign key linking to users.
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,                         -- User associated with the log.
    action TEXT NOT NULL,                    -- Action performed (e.g., login, update).
    resource TEXT NOT NULL,                  -- Resource affected.
    status TEXT NOT NULL,                    -- Status of the action (e.g., success, failure).
    ip TEXT NOT NULL,                        -- IP address of the action initiator.
    user_agent TEXT NOT NULL,                -- User agent of the initiator.
    details TEXT,                            -- Additional details about the action.
    created_at DATETIME NOT NULL,            -- Timestamp when the action occurred.
    FOREIGN KEY (user_id) REFERENCES users (id) -- Foreign key linking to users.
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_jti ON tokens(jti);
CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);`

type SQLiteDB struct {
	db *sql.DB
}

// NewSQLiteDB initializes a new SQLiteDB instance.
// - Enables foreign key support.
// - Ensures schema is created.
func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	// Ensures the connection to the database is valid
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}

	// Create schema
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}

	return &SQLiteDB{db: db}, nil
}

// User methods
// CreateUser inserts a new user into the users table.
func (s *SQLiteDB) CreateUser(user *models.User) error {
	_, err := s.db.Exec(`
        INSERT INTO users (
            username, password, role, created_at, updated_at, password_changed_at
        ) VALUES (?, ?, ?, ?, ?, ?)
    `, user.Username, user.Password, user.Role, time.Now(), time.Now(), time.Now())
	return err
}

// GetUserByUsername retrieves a user by their username.
// - Returns the user record or an error if not found.
func (s *SQLiteDB) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := s.db.QueryRow(`
        SELECT id, username, password, role, last_login_at,
               failed_attempts, locked_until, created_at, updated_at, password_changed_at
        FROM users WHERE username = ?
    `, username).Scan(
		&user.ID, &user.Username, &user.Password, &user.Role,
		&user.LastLoginAt, &user.FailedAttempts,
		&user.LockedUntil, &user.CreatedAt, &user.UpdatedAt, &user.PasswordChangedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// GetUserByID retrieves a user by their ID.
func (s *SQLiteDB) GetUserByID(id int64) (*models.User, error) {
	var user models.User
	err := s.db.QueryRow(`
        SELECT id, username, password, role, last_login_at, last_login_ip,
               failed_attempts, locked_until, password_changed_at,
               previous_passwords, created_at, updated_at
        FROM users
        WHERE id = ?
    `, id).Scan(
		&user.ID,
		&user.Username,
		&user.Password,
		&user.Role,
		&user.LastLoginAt,
		&user.LastLoginIP,
		&user.FailedAttempts,
		&user.LockedUntil,
		&user.PasswordChangedAt,
		&user.PreviousPasswords,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateUser updates user-specific details such as last login and failed attempts.
func (s *SQLiteDB) UpdateUser(user *models.User) error {
	_, err := s.db.Exec(`
        UPDATE users SET
            last_login_at = ?,
            last_login_ip = ?,
            failed_attempts = ?,
            locked_until = ?,
            updated_at = ?
        WHERE id = ?
    `, user.LastLoginAt, user.LastLoginIP, user.FailedAttempts,
		user.LockedUntil, time.Now(), user.ID)
	return err
}

// Token methods
// CreateToken inserts a new token into the tokens table.
func (s *SQLiteDB) CreateToken(token *models.Token) error {
	_, err := s.db.Exec(`
        INSERT INTO tokens (
            user_id, token, jti, expires_at, created_at,
            last_used_at, client_ip, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, token.UserID, token.Token, token.JTI, token.ExpiresAt,
		token.CreatedAt, token.LastUsedAt, token.ClientIP, token.UserAgent)
	return err
}

// GetTokenByJTI retrieves a token by its unique identifier.
func (s *SQLiteDB) GetTokenByJTI(jti string) (*models.Token, error) {
	var token models.Token
	err := s.db.QueryRow(`
        SELECT id, user_id, token, jti, expires_at, created_at,
               last_used_at, revoked_at, client_ip, user_agent
        FROM tokens WHERE jti = ?
    `, jti).Scan(
		&token.ID, &token.UserID, &token.Token, &token.JTI,
		&token.ExpiresAt, &token.CreatedAt, &token.LastUsedAt,
		&token.RevokedAt, &token.ClientIP, &token.UserAgent,
	)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// UpdateToken updates a token's last used and revoked timestamps.
func (s *SQLiteDB) UpdateToken(token *models.Token) error {
	_, err := s.db.Exec(`
        UPDATE tokens SET
            last_used_at = ?,
            revoked_at = ?
        WHERE id = ?
    `, token.LastUsedAt, token.RevokedAt, token.ID)
	return err
}

// CountActiveTokens returns the number of active tokens for a user.
func (s *SQLiteDB) CountActiveTokens(userID int64) (int, error) {
	var count int
	err := s.db.QueryRow(`
        SELECT COUNT(*) FROM tokens
        WHERE user_id = ?
        AND revoked_at IS NULL
        AND expires_at > ?
    `, userID, time.Now()).Scan(&count)
	return count, err
}

// CleanupExpiredTokens removes tokens that have expired or were revoked.
func (s *SQLiteDB) CleanupExpiredTokens() error {
	_, err := s.db.Exec(`
        DELETE FROM tokens
        WHERE expires_at < ?
        OR (revoked_at IS NOT NULL AND revoked_at < ?)
    `, time.Now(), time.Now().Add(-24*time.Hour))
	return err
}

// Audit methods
// CreateAuditLog inserts a new audit log into the audit_logs table.
func (s *SQLiteDB) CreateAuditLog(log *models.AuditLog) error {
	_, err := s.db.Exec(`
        INSERT INTO audit_logs (
            user_id, action, resource, status, ip,
            user_agent, details, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, log.UserID, log.Action, log.Resource, log.Status,
		log.IP, log.UserAgent, log.Details, time.Now())
	return err
}

// GetUserSessions retrieves all active sessions for a user.
func (s *SQLiteDB) GetUserSessions(userID int64) ([]models.Session, error) {
	rows, err := s.db.Query(`
        SELECT token, expires_at, last_used_at, revoked_at,
               client_ip, user_agent
        FROM tokens
        WHERE user_id = ?
        AND (revoked_at IS NULL OR revoked_at > ?)
        ORDER BY last_used_at DESC
    `, userID, time.Now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []models.Session
	for rows.Next() {
		var token models.Token
		var clientInfo struct {
			IP        string `json:"ip"`
			UserAgent string `json:"user_agent"`
		}

		err := rows.Scan(
			&token.Token, &token.ExpiresAt, &token.LastUsedAt,
			&token.RevokedAt, &clientInfo.IP, &clientInfo.UserAgent,
		)
		if err != nil {
			return nil, err
		}

		clientInfoJSON, _ := json.Marshal(clientInfo)

		sessions = append(sessions, models.Session{
			Token:      &token,
			LastUsed:   token.LastUsedAt,
			ClientInfo: string(clientInfoJSON),
			Active:     token.RevokedAt == nil && token.ExpiresAt.After(time.Now()),
		})
	}
	return sessions, nil
}

// UpdateUserPassword updates a user's password and previous passwords.
func (s *SQLiteDB) UpdateUserPassword(user *models.User) error {
	_, err := s.db.Exec(`
        UPDATE users SET
            password = ?,
            password_changed_at = ?,
            previous_passwords = ?,
            updated_at = ?
        WHERE id = ?
    `, user.Password, user.PasswordChangedAt, user.PreviousPasswords, user.UpdatedAt, user.ID)
	return err
}

// RevokeAllUserTokens revokes all active tokens for a user.
func (s *SQLiteDB) RevokeAllUserTokens(userID int64) error {
	now := time.Now()
	_, err := s.db.Exec(`
        UPDATE tokens
        SET revoked_at = ?
        WHERE user_id = ?
        AND revoked_at IS NULL
    `, now, userID)
	return err
}

// ListUsers retrieves a list of all users in the database.
func (s *SQLiteDB) ListUsers() ([]models.User, error) {
	rows, err := s.db.Query(`
        SELECT id, username, role, created_at, last_login_at
        FROM users
        ORDER BY id ASC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.Role,
			&user.CreatedAt,
			&user.LastLoginAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// GetTokenByRefreshToken retrieves a token by its refresh token and user ID.
func (s *SQLiteDB) GetTokenByRefreshToken(refreshToken string, userID int64) (*models.Token, error) {
	var token models.Token
	err := s.db.QueryRow(`
        SELECT id, user_id, token, refresh_token, expires_at, created_at,
               last_used_at, revoked_at, client_ip, user_agent, role
        FROM tokens
        WHERE refresh_token = ?
        AND user_id = ?
        AND revoked_at IS NULL
        AND expires_at > ?
    `, refreshToken, userID, time.Now()).Scan(
		&token.ID,
		&token.UserID,
		&token.Token,
		&token.RefreshToken,
		&token.ExpiresAt,
		&token.CreatedAt,
		&token.LastUsedAt,
		&token.RevokedAt,
		&token.ClientIP,
		&token.UserAgent,
		&token.Role,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("token not found or invalid")
		}
		return nil, err
	}
	return &token, nil
}
