package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	apierr "github.com/unkn0wn-root/terraster/internal/auth"
	"github.com/unkn0wn-root/terraster/internal/auth/models"
	"github.com/unkn0wn-root/terraster/internal/auth/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	Type         string    `json:"type"`
	ExpiresAt    time.Time `json:"expires_at"`
	Role         string    `json:"role"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.authService.AuthenticateUser(req.Username, req.Password, r)
	if err != nil {
		switch err {
		case apierr.ErrUserLocked:
			http.Error(w, "Account is temporarily locked", http.StatusForbidden)
		case apierr.ErrInvalidCredentials:
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		case apierr.ErrPasswordExpired:
			http.Error(w, "Password has expired", http.StatusUnauthorized)
		default:
			fmt.Println(err)
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
		}
		return
	}

	response := LoginResponse{
		Token:        token.Token,
		RefreshToken: token.RefreshToken,
		Type:         "Bearer",
		ExpiresAt:    token.ExpiresAt,
		Role:         string(token.Role),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if requester is admin
	claims := r.Context().Value("user_claims").(*jwt.MapClaims)
	if role := (*claims)["role"].(string); role != string(models.RoleAdmin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.authService.CreateUser(req.Username, req.Password, models.Role(req.Role))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *AuthHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.Header.Get("Authorization")
	if token == "" || len(token) < 7 || token[:7] != "Bearer " {
		http.Error(w, "Invalid authorization header", http.StatusBadRequest)
		return
	}

	if err := h.authService.RevokeToken(token[7:]); err != nil {
		http.Error(w, "Error revoking token", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.authService.RefreshToken(req.RefreshToken, r)
	if err != nil {
		switch err {
		case apierr.ErrInvalidToken:
			http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		case apierr.ErrRevokedToken:
			http.Error(w, "Refresh token has been revoked", http.StatusUnauthorized)
		default:
			http.Error(w, "Error refreshing token", http.StatusInternalServerError)
		}
		return
	}

	response := LoginResponse{
		Token:        token.Token,
		RefreshToken: token.RefreshToken,
		Type:         "Bearer",
		ExpiresAt:    token.ExpiresAt,
		Role:         string(token.Role),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	claims := r.Context().Value("user_claims").(*jwt.MapClaims)
	userID := int64((*claims)["user_id"].(float64))

	sessions, err := h.authService.GetActiveSessions(userID)
	if err != nil {
		http.Error(w, "Error fetching sessions", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

// Add to AuthHandler
func (h *AuthHandler) GetPasswordRequirements(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := h.authService.GetConfig()

	requirements := map[string]interface{}{
		"minLength": config.PasswordMinLength,
		"maxLength": 128,
		"requires": map[string]bool{
			"uppercase": config.RequireUppercase,
			"lowercase": true,
			"number":    config.RequireNumber,
			"special":   config.RequireSpecialChar,
		},
		"preventions": []string{
			"3 or more consecutive identical characters",
			"Sequential characters (abc, 123)",
			"Username in password",
			"Common passwords",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requirements)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get user from context
	claims := r.Context().Value("user_claims").(*jwt.MapClaims)
	userID := int64((*claims)["user_id"].(float64))

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.authService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		switch err {
		case apierr.ErrPasswordExpired:
			http.Error(w, "Password has expired and must be changed", http.StatusForbidden)
		case apierr.ErrInvalidCredentials:
			http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
