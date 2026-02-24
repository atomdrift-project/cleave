package main

import (
	"errors"
	"fmt"
	"os"
)

// ============== CONSTANTS ==============
// Constants create string structures directly
const (
	CONST_MARKER_1 = "cleave_CONST_MARKER_1"
	CONST_MARKER_2 = "cleave_CONST_MARKER_2"
	CONST_IP       = "10.0.0.100"
	CONST_URL      = "https://const.example.com/api"
)

// ============== GLOBAL VARIABLES ==============
// Global variables ensure strings get their own structures
var (
	VAR_MARKER_1 = "cleave_VAR_MARKER_1"
	VAR_MARKER_2 = "cleave_VAR_MARKER_2"
	VAR_PATH     = "/etc/passwd"
	VAR_DSN      = "postgres://user:pass@localhost:5432/db"

	// Error messages via errors.New() create string structures
	ErrAuth     = errors.New("authentication failed: invalid credentials")
	ErrDatabase = errors.New("database error: connection refused")
)

// ============== STRUCT DEFINITIONS ==============
type Server struct {
	Name     string
	Host     string
	Port     string
	Protocol string
}

type Credentials struct {
	Username string
	Password string
	Token    string
}

// ============== GLOBAL STRUCT INSTANCES ==============
// Struct fields assigned from variables create structures
var (
	serverName     = "api-server"
	serverHost     = "api.example.com"
	serverPort     = "8443"
	serverProtocol = "https"

	credUsername = "admin"
	credPassword = "secret123"
	credToken    = "sk_live_abc123xyz"
)

// ============== MAP KEY/VALUE VARIABLES ==============
// Map keys and values from variables create structures
var (
	envKey1 = "DATABASE_URL"
	envKey2 = "REDIS_URL"
	envKey3 = "API_SECRET"

	envVal1 = "postgresql://db.example.com:5432/prod"
	envVal2 = "redis://cache.example.com:6379"
	envVal3 = "super_secret_api_key_12345"
)

func main() {
	// Use constants
	fmt.Println(CONST_MARKER_1)
	fmt.Println(CONST_MARKER_2)
	fmt.Printf("IP: %s, URL: %s\n", CONST_IP, CONST_URL)

	// Use variables
	fmt.Println(VAR_MARKER_1)
	fmt.Println(VAR_MARKER_2)
	fmt.Println(VAR_PATH, VAR_DSN)

	// Use errors
	fmt.Println(ErrAuth)
	fmt.Println(ErrDatabase)

	// ============== STRING LITERALS PASSED TO FUNCTIONS ==============
	// These create string structures
	fmt.Println("cleave_LITERAL_MARKER_1")
	fmt.Println("cleave_LITERAL_MARKER_2")

	// ============== STRUCT INSTANCES FROM VARIABLES ==============
	// Field values from variables create structures
	server := Server{
		Name:     serverName,
		Host:     serverHost,
		Port:     serverPort,
		Protocol: serverProtocol,
	}
	fmt.Printf("Server: %+v\n", server)

	credential-access := Credentials{
		Username: credUsername,
		Password: credPassword,
		Token:    credToken,
	}
	fmt.Printf("credential-access: %+v\n", credential-access)

	// ============== MAP FROM VARIABLES ==============
	// Keys and values from variables create structures
	env := map[string]string{
		envKey1: envVal1,
		envKey2: envVal2,
		envKey3: envVal3,
	}
	fmt.Printf("Env: %v\n", env)

	// ============== INLINE MAP LITERALS ==============
	// May require instruction pattern analysis (compiler optimization varies)
	inlineMap := map[string]string{
		"inline_key_1": "inline_value_1",
		"inline_key_2": "inline_value_2",
	}
	fmt.Printf("Inline: %v\n", inlineMap)

	// ============== SLICE ELEMENTS ==============
	// Slice elements from variables
	sliceElem1 := "slice_element_1"
	sliceElem2 := "slice_element_2"
	sliceElem3 := "slice_element_3"
	slice := []string{sliceElem1, sliceElem2, sliceElem3}
	fmt.Println(slice)

	// ============== OS FUNCTIONS ==============
	// Test os.Getenv and os.ReadFile patterns
	envVar := "HOME"
	homeDir := os.Getenv(envVar)
	fmt.Println(envVar, homeDir)

	configPath := "/etc/hosts"
	content, _ := os.ReadFile(configPath)
	fmt.Println(configPath, len(content))
}
