package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// walkDirs recursively finds all files in the given directories.
// Returns a channel of absolute file paths.
func walkDirs(ctx context.Context, dirs []string) (<-chan string, error) {
	paths := make(chan string, 100)

	go func() {
		defer close(paths)
		for _, dir := range dirs {
			if err := walkDir(ctx, dir, paths); err != nil {
				// Log error but continue with other directories
				continue
			}
		}
	}()

	return paths, nil
}

// walkDir walks a single directory and sends file paths to the channel.
func walkDir(ctx context.Context, root string, paths chan<- string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// Check for cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // Skip files we can't access
		}

		// Skip hidden directories
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") && name != "." {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		// Skip symlinks (to avoid infinite loops)
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		// Get absolute path
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil
		}

		// Check file is readable
		if _, err := os.Stat(absPath); err != nil {
			return nil
		}

		paths <- absPath
		return nil
	})
}

