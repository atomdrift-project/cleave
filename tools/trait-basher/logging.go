package main

import (
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// retryDelay returns a duration of 2 minutes plus a random amount up to 60 seconds.
// Uses math/rand/v2 which is automatically seeded and thread-safe.
func retryDelay() time.Duration {
	baseDelay := 2 * time.Minute
	randomDelay := time.Duration(mathrand.Int64N(int64(60 * time.Second))) //nolint:gosec // non-cryptographic use
	return baseDelay + randomDelay
}

// formatProvidersForDisplay collapses gemini:model entries into a single "gemini (N models)"
// for cleaner display while showing the full fallback chain.
func formatProvidersForDisplay(providers []string) string {
	var result []string
	geminiCount := 0

	flushGemini := func() {
		if geminiCount == 0 {
			return
		}
		if geminiCount == 1 {
			result = append(result, "gemini")
		} else {
			result = append(result, fmt.Sprintf("gemini (%d models)", geminiCount))
		}
		geminiCount = 0
	}

	for _, p := range providers {
		switch {
		case strings.HasPrefix(p, "gemini:"):
			geminiCount++
		case p == "gemini":
			result = append(result, "gemini")
		default:
			flushGemini()
			result = append(result, p)
		}
	}
	flushGemini()
	return strings.Join(result, " → ")
}

// getLogDir returns the platform-appropriate log directory for trait-basher.
//   - macOS: ~/Library/Logs/trait-basher/
//   - Linux: ~/.local/state/trait-basher/ (XDG Base Directory spec)
//   - Windows: %LOCALAPPDATA%\trait-basher\logs\.
func getLogDir() (string, error) {
	var logDir string

	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		logDir = filepath.Join(home, "Library", "Logs", "trait-basher")

	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		logDir = filepath.Join(localAppData, "trait-basher", "logs")

	default:
		stateHome := os.Getenv("XDG_STATE_HOME")
		if stateHome == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			stateHome = filepath.Join(home, ".local", "state")
		}
		logDir = filepath.Join(stateHome, "trait-basher")
	}

	if err := os.MkdirAll(logDir, 0o755); err != nil { //nolint:gosec // logs need user readability
		return "", fmt.Errorf("could not create log directory %s: %w", logDir, err)
	}
	return logDir, nil
}

// getLogFilePath returns the path for trait-basher's archive review logs.
func getLogFilePath(sessionID string) (string, error) {
	logDir, err := getLogDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(logDir, fmt.Sprintf("archives-%s.log", sessionID)), nil
}

// getflayerLogFilePath returns the path for flayer's own verbose logs.
func getflayerLogFilePath(sessionID string) (string, error) {
	logDir, err := getLogDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(logDir, fmt.Sprintf("flayer-%s.log", sessionID)), nil
}

// generateSessionID returns a UUID v4 for session tracking.
func generateSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)         //nolint:errcheck // crypto/rand.Read never fails on supported platforms
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
