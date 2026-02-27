package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// openDB opens or creates the SQLite database for tracking analyzed files.
func openDB(ctx context.Context, flush bool) (*sql.DB, error) {
	// Determine config directory (platform-specific)
	var base string
	switch runtime.GOOS {
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("config directory: %w", err)
		}
		base = filepath.Join(home, "Library", "Application Support")
	default:
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			base = xdg
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, fmt.Errorf("config directory: %w", err)
			}
			base = filepath.Join(home, ".config")
		}
	}
	dir := filepath.Join(base, "cleave")

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create config directory: %w", err)
	}

	dbPath := filepath.Join(dir, "trait-basher.db")

	if flush {
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("remove database: %w", err)
		}
		fmt.Fprintf(os.Stderr, "%s✓%s Flushed analysis cache: %s\n", colorGreen, colorReset, dbPath)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS analyzed_files (
			file_hash TEXT NOT NULL,
			mode TEXT NOT NULL,
			analyzed_at INTEGER NOT NULL,
			PRIMARY KEY (file_hash, mode)
		)
	`)
	if err != nil {
		db.Close() //nolint:errcheck,gosec // best-effort cleanup on error
		return nil, fmt.Errorf("create table: %w", err)
	}

	return db, nil
}

// hashFile returns SHA256 hash of a file's contents.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close() //nolint:errcheck // best-effort cleanup

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashString returns SHA256 hash of a string (for archive path caching).
func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// wasAnalyzed checks if a file hash has already been analyzed in the given mode.
func wasAnalyzed(ctx context.Context, db *sql.DB, hash, mode string) bool {
	var n int
	err := db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM analyzed_files WHERE file_hash = ? AND mode = ?",
		hash, mode,
	).Scan(&n)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  [warn] DB query failed: %v\n", err)
		return false
	}
	return n > 0
}

// markAnalyzed records that a file hash has been analyzed in the given mode.
func markAnalyzed(ctx context.Context, db *sql.DB, hash, mode string) error {
	_, err := db.ExecContext(ctx,
		"INSERT OR REPLACE INTO analyzed_files (file_hash, mode, analyzed_at) VALUES (?, ?, ?)",
		hash, mode, time.Now().Unix(),
	)
	return err
}

// saveTrainingData saves raw cleave JSONL output to a file named after the source file's SHA256.
// If the file already exists, it's skipped (idempotent).
// The rawJSONL should be the original line from cleave output.
func saveTrainingData(trainingDir, sourcePath, rawJSONL string) error {
	if trainingDir == "" {
		return nil // Training data output disabled
	}

	// Get SHA256 of the source file
	fileHash, err := hashFile(sourcePath)
	if err != nil {
		// For archive members or virtual paths, use path hash
		fileHash = hashString(sourcePath)
	}

	outPath := filepath.Join(trainingDir, fileHash+".jsonl")

	// Skip if already exists (idempotent)
	if _, err := os.Stat(outPath); err == nil {
		return nil
	}

	// Write raw JSONL data (preserves full cleave output for feature extraction)
	return os.WriteFile(outPath, []byte(rawJSONL+"\n"), 0o644) //nolint:gosec // training data needs readability
}

// cleanupOrphanedExtractDirs removes tbsh.<pid> directories where the
// owning process no longer exists. This handles cleanup after crashes or kill -9.
func cleanupOrphanedExtractDirs() {
	tmpDir := os.TempDir()
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}

	const prefix = "tbsh."
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}

		// Extract PID from directory name
		pidStr := strings.TrimPrefix(entry.Name(), prefix)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue // Not a valid PID format
		}

		// Check if process is still running (signal 0 = check existence)
		if err := syscall.Kill(pid, 0); err == nil {
			continue // Process still running, don't clean up
		}

		// Process is dead, clean up orphaned directory
		orphanPath := filepath.Join(tmpDir, entry.Name())
		fmt.Fprintf(os.Stderr, "%s⚡%s Cleaning up orphaned extract directory: %s%s%s\n", colorYellow, colorReset, colorDim, orphanPath, colorReset)
		os.RemoveAll(orphanPath) //nolint:errcheck,gosec // best-effort cleanup
	}
}

// getProcessRSSMB returns the RSS (resident set size) of a process in megabytes.
// Returns 0 if the process doesn't exist or RSS can't be determined.
func getProcessRSSMB(pid int) int {
	switch runtime.GOOS {
	case "linux":
		// Read from /proc/<pid>/statm - second field is RSS in pages
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
		if err != nil {
			return 0
		}
		fields := strings.Fields(string(data))
		if len(fields) < 2 {
			return 0
		}
		rssPages, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		// Convert pages to MB (page size is typically 4KB)
		pageSize := int64(syscall.Getpagesize())
		return int(rssPages * pageSize / (1024 * 1024))

	case "darwin":
		// Read from /proc doesn't work on macOS, use ps command
		// ps -o rss= returns RSS in KB
		out, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
		if err == nil {
			// Rosetta/Linux compat layer might work
			fields := strings.Fields(string(out))
			if len(fields) >= 2 {
				if rssPages, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return int(rssPages * int64(syscall.Getpagesize()) / (1024 * 1024))
				}
			}
		}
		// Fallback: can't easily get RSS on macOS without exec, return 0
		return 0

	default:
		return 0
	}
}
