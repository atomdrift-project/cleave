package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// clearProgressLine clears the current terminal line.
func clearProgressLine() {
	fmt.Fprint(os.Stderr, "\r\033[K")
}

// formatProgress returns a formatted progress string with stats and colors.
// Example: "[1234/5678 22%] Det:94% | 52/s | path/to/file.bat".
func formatProgress(current, total int, detectionRate float64, filesPerSec float64, currentPath string, knownGood bool) string {
	var sb strings.Builder

	if total > 0 {
		pct := float64(current) / float64(total) * 100
		pctColor := rateColor(pct)
		sb.WriteString(fmt.Sprintf("%s[%d/%d %.0f%%]%s", pctColor, current, total, pct, colorReset))
	} else {
		sb.WriteString(fmt.Sprintf("%s[%d]%s", colorCyan, current, colorReset))
	}

	if current > 0 {
		rateClr := rateColor(detectionRate)
		if knownGood {
			sb.WriteString(fmt.Sprintf(" %sClean:%.2f%%%s", rateClr, detectionRate, colorReset))
		} else {
			sb.WriteString(fmt.Sprintf(" %sDet:%.2f%%%s", rateClr, detectionRate, colorReset))
		}
	}

	if filesPerSec > 0 {
		sb.WriteString(fmt.Sprintf(" %s|%s %s%.0f/s%s", colorDim, colorReset, colorCyan, filesPerSec, colorReset))
	}

	sb.WriteString(fmt.Sprintf(" %s|%s ", colorDim, colorReset))
	sb.WriteString(currentPath)

	return sb.String()
}

// countFiles quickly counts files in directories for progress estimation.
func countFiles(dirs []string) int {
	count := 0
	for _, dir := range dirs {
		_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error { //nolint:errcheck // best-effort counting
			if err != nil {
				return nil //nolint:nilerr // intentionally skip errors and continue counting
			}
			if !d.IsDir() {
				count++
			}
			return nil
		})
	}
	return count
}
