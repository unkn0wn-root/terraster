package util

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/unkn0wn-root/go-load-balancer/internal/auth/database"
	"github.com/unkn0wn-root/go-load-balancer/internal/auth/models"
	"github.com/unkn0wn-root/go-load-balancer/internal/auth/service"
)

type Config struct {
	DBPath             string
	JWTSecret          string
	PasswordMinLength  int
	RequireUppercase   bool
	RequireNumber      bool
	RequireSpecialChar bool
}

func main() {
	var (
		username  = flag.String("username", "", "Username for the new user")
		password  = flag.String("password", "", "Password for the new user")
		role      = flag.String("role", "reader", "Role for the new user (admin or reader)")
		dbPath    = flag.String("db", "./auth.db", "Path to SQLite database")
		listUsers = flag.Bool("list", false, "List all users")
	)

	flag.Parse()

	// Initialize configuration
	config := Config{
		DBPath:             *dbPath,
		JWTSecret:          "your-jwt-secret", // In production, load from env or config file
		PasswordMinLength:  12,
		RequireUppercase:   true,
		RequireNumber:      true,
		RequireSpecialChar: true,
	}

	// Initialize database
	db, err := database.NewSQLiteDB(config.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize auth service
	authService := service.NewAuthService(db, service.AuthConfig{
		JWTSecret:          []byte(config.JWTSecret),
		TokenExpiry:        7 * 24 * 60 * 60,   // 7 days
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7-day refresh token
		MaxLoginAttempts:   5,
		LockDuration:       15 * 60, // 15 minutes
		MaxActiveTokens:    5,
		PasswordMinLength:  config.PasswordMinLength,
		RequireUppercase:   config.RequireUppercase,
		RequireNumber:      config.RequireNumber,
		RequireSpecialChar: config.RequireSpecialChar,
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
