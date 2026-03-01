package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// cleaveServer manages a cleave server subprocess.
type cleaveServer struct {
	cmd     *exec.Cmd
	port    int
	baseURL string
	client  *http.Client
}

// pickPort finds an available TCP port.
func pickPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port, nil
}

// startCleaveServer starts cleave in server mode and waits for it to be ready.
func startCleaveServer(ctx context.Context, cfg *config) (*cleaveServer, error) {
	port, err := pickPort()
	if err != nil {
		return nil, fmt.Errorf("could not pick port: %w", err)
	}

	bind := fmt.Sprintf("127.0.0.1:%d", port)

	// Build comma-separated list of allowed directories
	allowedPaths := strings.Join(cfg.dirs, ",")

	args := []string{
		"server",
		"--bind", bind,
		"--dangerous-local-file-paths", allowedPaths,
		"--extract-dir", cfg.extractDir,
		"--timeout", "300", // 5 minutes per file
	}

	cmd := exec.CommandContext(ctx, cfg.cleaveBin, args...) //nolint:gosec // cleaveBin is built from trusted cargo
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot
	}

	// Inherit stderr so we see server output
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start cleave server: %w", err)
	}

	s := &cleaveServer{
		cmd:     cmd,
		port:    port,
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		client: &http.Client{
			Timeout: 10 * time.Minute, // Long timeout for large files
		},
	}

	fmt.Fprintf(os.Stderr, "Started cleave server on %s (PID %d)\n", bind, cmd.Process.Pid)

	// Wait for server to be ready
	if err := s.waitReady(ctx); err != nil {
		s.stop()
		return nil, fmt.Errorf("server failed to become ready: %w", err)
	}

	return s, nil
}

// waitReady polls /health until the server is ready.
func (s *cleaveServer) waitReady(ctx context.Context) error {
	healthURL := s.baseURL + "/health"

	// Poll every 500ms for up to 2 minutes (accounts for 27s YARA load)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	timeout := time.After(2 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for server to be ready")
		case <-ticker.C:
			resp, err := s.client.Get(healthURL)
			if err != nil {
				continue // Server not ready yet
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(os.Stderr, "cleave server ready\n")
				return nil
			}
		}
	}
}

// stop terminates the server process.
func (s *cleaveServer) stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	fmt.Fprintf(os.Stderr, "Stopping cleave server (PID %d)\n", s.cmd.Process.Pid)
	if err := s.cmd.Process.Kill(); err != nil {
		return err
	}
	s.cmd.Wait() //nolint:errcheck // best effort
	return nil
}

// AnalysisReport mirrors the Rust AnalysisReport struct (subset of fields we need).
type AnalysisReport struct {
	Target        TargetInfo      `json:"target"`
	Findings      []ServerFinding `json:"findings"`
	ExtractedPath string          `json:"extracted_path,omitempty"`
}

// TargetInfo mirrors the Rust TargetInfo struct.
type TargetInfo struct {
	Path     string `json:"path"`
	FileType string `json:"type"`
	SHA256   string `json:"sha256"`
}

// ServerFinding mirrors the Rust Finding struct.
type ServerFinding struct {
	ID   string `json:"id"`
	Desc string `json:"desc,omitempty"`
	Crit string `json:"crit,omitempty"`
}

// analyzePath sends a file path to the server for analysis.
func (s *cleaveServer) analyzePath(ctx context.Context, path string) (*AnalysisReport, error) {
	reqBody, err := json.Marshal(map[string]string{"path": path})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", s.baseURL+"/analyze-path", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, errResp.Error)
	}

	var report AnalysisReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &report, nil
}

// toJSONLEntry converts an AnalysisReport to the jsonlEntry format expected by trait-basher.
func (r *AnalysisReport) toJSONLEntry() jsonlEntry {
	// Convert ServerFinding to Finding
	findings := make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		crit := f.Crit
		if crit == "" {
			crit = "baseline"
		}
		// Handle lowercase crit from JSON (serde uses lowercase by default)
		crit = strings.ToLower(crit)
		findings[i] = Finding{
			ID:   f.ID,
			Crit: crit,
			Desc: f.Desc,
		}
	}

	// Determine risk level from highest finding criticality
	risk := "baseline"
	for _, f := range findings {
		if critRank[f.Crit] > critRank[risk] {
			risk = f.Crit
		}
	}

	return jsonlEntry{
		Type:          "file",
		Path:          r.Target.Path,
		FileType:      r.Target.FileType,
		Risk:          risk,
		Findings:      findings,
		ExtractedPath: r.ExtractedPath,
	}
}
