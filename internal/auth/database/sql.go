package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/unkn0wn-root/go-load-balancer/internal/auth/models"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    last_login_at DATETIME,
    last_login_ip TEXT,
    failed_attempts INTEGER DEFAULT 0,
    locked_until DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    password_changed_at DATETIME NOT NULL,
    previous_passwords TEXT -- Store as JSON array of hashed passwords
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    jti TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    last_used_at DATETIME NOT NULL,
    revoked_at DATETIME,
    client_ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    status TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    details TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id)
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

func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
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
func (s *SQLiteDB) CreateUser(user *models.User) error {
	_, err := s.db.Exec(`
        INSERT INTO users (
            username, password, role, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?)
    `, user.Username, user.Password, user.Role, time.Now(), time.Now())
	return err
}

func (s *SQLiteDB) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := s.db.QueryRow(`
        SELECT id, username, password, role, last_login_at, last_login_ip,
               failed_attempts, locked_until, created_at, updated_at
        FROM users WHERE username = ?
    `, username).Scan(
		&user.ID, &user.Username, &user.Password, &user.Role,
		&user.LastLoginAt, &user.LastLoginIP, &user.FailedAttempts,
		&user.LockedUntil, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

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
		if err == sql.ErrNoRows {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

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

func (s *SQLiteDB) UpdateToken(token *models.Token) error {
	_, err := s.db.Exec(`
        UPDATE tokens SET
            last_used_at = ?,
            revoked_at = ?
        WHERE id = ?
    `, token.LastUsedAt, token.RevokedAt, token.ID)
	return err
}

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

func (s *SQLiteDB) CleanupExpiredTokens() error {
	_, err := s.db.Exec(`
        DELETE FROM tokens
        WHERE expires_at < ?
        OR (revoked_at IS NOT NULL AND revoked_at < ?)
    `, time.Now(), time.Now().Add(-24*time.Hour))
	return err
}

// Audit methods
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
