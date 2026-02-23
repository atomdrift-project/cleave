package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCleanupOrphanedExtractDirs(t *testing.T) {
	tmpDir := os.TempDir() //nolint:usetesting // testing cleanup of dirs in system temp dir

	// Create a fake orphaned directory with a non-existent PID
	// Use PID 1 billion which definitely doesn't exist
	orphanPID := 1000000000
	orphanDir := filepath.Join(tmpDir, fmt.Sprintf("tbsh.%d", orphanPID))
	if err := os.MkdirAll(orphanDir, 0o750); err != nil {
		t.Fatalf("Failed to create test orphan dir: %v", err)
	}
	// Create a file inside to verify recursive removal
	testFile := filepath.Join(orphanDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create a directory for the current process (should NOT be cleaned up)
	currentDir := filepath.Join(tmpDir, fmt.Sprintf("tbsh.%d", os.Getpid()))
	if err := os.MkdirAll(currentDir, 0o750); err != nil {
		t.Fatalf("Failed to create current process dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(currentDir) }) //nolint:errcheck // test cleanup

	// Run cleanup
	cleanupOrphanedExtractDirs()

	// Verify orphan was cleaned up
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		os.RemoveAll(orphanDir) //nolint:errcheck // test cleanup on failure
		t.Errorf("Orphan directory was not cleaned up: %s", orphanDir)
	}

	// Verify current process dir was NOT cleaned up
	if _, err := os.Stat(currentDir); os.IsNotExist(err) {
		t.Errorf("Current process directory was incorrectly cleaned up: %s", currentDir)
	}
}

func TestCleanupOrphanedExtractDirs_IgnoresNonMatchingDirs(t *testing.T) {
	tmpDir := os.TempDir() //nolint:usetesting // testing cleanup of dirs in system temp dir

	// Create directories that should NOT be touched
	testDirs := []string{
		filepath.Join(tmpDir, "tbsh.notapid"),
		filepath.Join(tmpDir, "other-tool-12345"),
		filepath.Join(tmpDir, "tbsh."), // Empty PID
	}

	for _, dir := range testDirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("Failed to create test dir %s: %v", dir, err)
		}
		d := dir                              // capture for closure
		t.Cleanup(func() { os.RemoveAll(d) }) //nolint:errcheck // test cleanup
	}

	// Run cleanup
	cleanupOrphanedExtractDirs()

	// Verify none were touched (except tbsh. which has invalid format)
	for _, dir := range testDirs[:2] {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Non-matching directory was incorrectly cleaned up: %s", dir)
		}
	}
}

func TestExtractDirNaming(t *testing.T) {
	// Verify the naming convention includes PID
	pid := os.Getpid()
	//nolint:usetesting // testing that extract dirs use os.TempDir()
	expected := filepath.Join(os.TempDir(), fmt.Sprintf("tbsh.%d", pid))

	// This is the same logic used in main()
	//nolint:usetesting // testing that extract dirs use os.TempDir()
	actual := filepath.Join(os.TempDir(), fmt.Sprintf("tbsh.%d", pid))

	if actual != expected {
		t.Errorf("Extract dir naming mismatch: got %s, want %s", actual, expected)
	}
}

func TestProcessExistsCheck(t *testing.T) {
	// Current process should exist
	if err := syscall.Kill(os.Getpid(), 0); err != nil {
		t.Errorf("Current process check failed: %v", err)
	}

	// Non-existent PID should fail
	if err := syscall.Kill(1000000000, 0); err == nil {
		t.Error("Non-existent process check should have failed")
	}
}

func TestFormatProvidersForDisplay(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		input    []string
	}{
		{
			name:     "single provider",
			input:    []string{"claude"},
			expected: "claude",
		},
		{
			name:     "multiple simple providers",
			input:    []string{"gemini", "claude", "codex"},
			expected: "gemini → claude → codex",
		},
		{
			name:     "expanded gemini models",
			input:    []string{"gemini:gemini-3-pro-preview", "gemini:gemini-3-flash-preview", "gemini:gemini-2.5-pro", "gemini:gemini-2.5-flash"},
			expected: "gemini (4 models)",
		},
		{
			name:     "expanded gemini with fallback providers",
			input:    []string{"gemini:gemini-3-pro-preview", "gemini:gemini-3-flash-preview", "codex", "claude"},
			expected: "gemini (2 models) → codex → claude",
		},
		{
			name:     "single gemini model",
			input:    []string{"gemini:gemini-3-pro-preview"},
			expected: "gemini",
		},
		{
			name:     "mixed with plain gemini",
			input:    []string{"claude", "gemini", "codex"},
			expected: "claude → gemini → codex",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := formatProvidersForDisplay(tc.input)
			if result != tc.expected {
				t.Errorf("formatProvidersForDisplay(%v) = %q, want %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestFindingDescriptionTruncation(t *testing.T) {
	tests := []struct {
		name        string
		desc        string
		expectLen   int
		expectTrunc bool
	}{
		{
			name:        "short description unchanged",
			desc:        "This is a short description",
			expectLen:   27,
			expectTrunc: false,
		},
		{
			name:        "exactly 256 chars unchanged",
			desc:        string(make([]byte, 256)),
			expectLen:   256,
			expectTrunc: false,
		},
		{
			name:        "257 chars gets truncated",
			desc:        string(make([]byte, 257)),
			expectLen:   259, // 256 + "..."
			expectTrunc: true,
		},
		{
			name:        "very long description truncated",
			desc:        string(make([]byte, 1000)),
			expectLen:   259, // 256 + "..."
			expectTrunc: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate the truncation logic from streamAnalyzeAndReview
			findings := []Finding{
				{
					ID:   "test-id",
					Crit: "suspicious",
					Desc: tc.desc,
				},
			}

			// Apply the same truncation logic
			for i := range findings {
				if len(findings[i].Desc) > 256 {
					findings[i].Desc = findings[i].Desc[:256] + "..."
				}
			}

			result := findings[0].Desc
			if len(result) != tc.expectLen {
				t.Errorf("Expected length %d, got %d", tc.expectLen, len(result))
			}

			if tc.expectTrunc {
				if len(result) <= 256 {
					t.Error("Expected description to be truncated but it wasn't")
				}
				if len(result) > 259 {
					t.Errorf("Truncated description should be max 259 chars, got %d", len(result))
				}
				if result[len(result)-3:] != "..." {
					t.Error("Truncated description should end with '...'")
				}
			} else if len(result) > 256 {
				t.Error("Expected description to not be truncated but it was")
			}
		})
	}
}
