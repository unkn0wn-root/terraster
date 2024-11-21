package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/unkn0wn-root/terraster/internal/auth/database"
	"github.com/unkn0wn-root/terraster/internal/auth/models"
	"github.com/unkn0wn-root/terraster/internal/auth/service"
	"github.com/unkn0wn-root/terraster/internal/config"
)

type Config struct {
	DBPath               string
	JWTSecret            string
	PasswordMinLength    int
	TokenCleanupInterval string
	RequireUppercase     bool
	RequireNumber        bool
	RequireSpecialChar   bool
}

func main() {
	var (
		username   = flag.String("username", "", "Username for the new user")
		password   = flag.String("password", "", "Password for the new user")
		role       = flag.String("role", "reader", "Role for the new user (admin or reader)")
		listUsers  = flag.Bool("list", false, "List all users")
		configPath = flag.String("config", "./db.yaml", "Path to configuration file")
	)
	flag.Parse()
	if *configPath == "" {
		log.Fatalf("Config file path is required")
	}

	cfg, err := config.LoadAPIConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize configuration
	apiCfg := Config{
		DBPath:               cfg.DBPath,
		JWTSecret:            cfg.JWTSecret,
		PasswordMinLength:    cfg.PasswordMinLength,
		TokenCleanupInterval: cfg.TokenCleanupInterval,
		RequireUppercase:     true,
		RequireNumber:        true,
		RequireSpecialChar:   true,
	}

	// Initialize database
	db, err := database.NewSQLiteDB(apiCfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	tokenDuration, err := time.ParseDuration(apiCfg.TokenCleanupInterval)
	if err != nil {
		tokenDuration = 24 * time.Hour
	}

	// Initialize auth service
	authService := service.NewAuthService(db, service.AuthConfig{
		JWTSecret:            []byte(apiCfg.JWTSecret),
		TokenExpiry:          7 * 24 * 60 * 60, // 7 days
		TokenCleanupInterval: tokenDuration,
		RefreshTokenExpiry:   7 * 24 * time.Hour, // 7-day refresh token
		MaxLoginAttempts:     5,
		LockDuration:         15 * 60, // 15 minutes
		MaxActiveTokens:      5,
		PasswordMinLength:    apiCfg.PasswordMinLength,
		RequireUppercase:     apiCfg.RequireUppercase,
		RequireNumber:        apiCfg.RequireNumber,
		RequireSpecialChar:   apiCfg.RequireSpecialChar,
	})

	// Handle list users command
	if *listUsers {
		if err := listAllUsers(db); err != nil {
			log.Fatalf("Failed to list users: %v", err)
		}
		return
	}

	// Validate inputs for user creation
	if *username == "" || *password == "" {
		flag.Usage()
		os.Exit(1)
	}

	// Validate role
	userRole := models.Role(*role)
	if userRole != models.RoleAdmin && userRole != models.RoleReader {
		log.Fatalf("Invalid role. Must be 'admin' or 'reader'")
	}

	// Create user
	err = authService.CreateUser(*username, *password, userRole)
	if err != nil {
		log.Fatalf("Failed to create user: %v", err)
	}

	fmt.Printf("Successfully created user '%s' with role '%s'\n", *username, *role)
}

func listAllUsers(db *database.SQLiteDB) error {
	users, err := db.ListUsers()
	if err != nil {
		return err
	}

	if len(users) == 0 {
		fmt.Println("No users found in database")
		return nil
	}

	fmt.Println("\nUser List:")
	fmt.Println("----------------------------------------")
	fmt.Printf("%-5s %-20s %-10s %-20s\n", "ID", "Username", "Role", "Created At")
	fmt.Println("----------------------------------------")

	for _, user := range users {
		fmt.Printf("%-5d %-20s %-10s %-20s\n",
			user.ID,
			user.Username,
			user.Role,
			user.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	fmt.Println("----------------------------------------")
	return nil
}
