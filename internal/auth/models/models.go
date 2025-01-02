package models

import (
	"time"
)

type Role string

const (
	RoleAdmin  Role = "admin"
	RoleReader Role = "reader"
)

type User struct {
	ID                int64      `json:"id"`
	Username          string     `json:"username"`
	Password          string     `json:"-"`
	Role              Role       `json:"role"`
	LastLoginAt       *time.Time `json:"last_login_at"`
	LastLoginIP       string     `json:"last_login_ip"`
	FailedAttempts    int        `json:"-"`
	LockedUntil       *time.Time `json:"-"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	PasswordChangedAt time.Time  `json:"password_changed_at"`
}

type Token struct {
	ID           int64      `json:"id"`
	UserID       int64      `json:"user_id"`
	Token        string     `json:"token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   time.Time  `json:"last_used_at"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	ClientIP     string     `json:"client_ip"`
	UserAgent    string     `json:"user_agent"`
	JTI          string     `json:"-"` // JWT ID for tracking
	Role         Role       `json:"role"`
}

type AuditLog struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Status    string    `json:"status"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Details   string    `json:"details"`
	CreatedAt time.Time `json:"created_at"`
}

type Session struct {
	Token      *Token    `json:"token"`
	LastUsed   time.Time `json:"last_used"`
	ClientInfo string    `json:"client_info"`
	Active     bool      `json:"active"`
}
