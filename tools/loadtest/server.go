package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type cleaveServer struct {
	cmd     *exec.Cmd
	logFile *os.File
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

// startServer builds and starts a cleave server subprocess.
func startServer(ctx context.Context, cleaveBin string) (*cleaveServer, error) {
	if cleaveBin == "" {
		// Try to find cleave in PATH.
		var err error
		cleaveBin, err = exec.LookPath("cleave")
		if err != nil {
			return nil, fmt.Errorf("cleave binary not found in PATH; use --cleave-bin or build first")
		}
	}

	port, err := pickPort()
	if err != nil {
		return nil, fmt.Errorf("pick port: %w", err)
	}

	bind := fmt.Sprintf("127.0.0.1:%d", port)
	args := []string{
		"server",
		"--bind", bind,
		"--qps", "0", // 0 = unlimited (no rate limiting)
		"--timeout", "300",
	}

	logFile, err := os.CreateTemp("", "cleave-loadtest-*.log")
	if err != nil {
		return nil, fmt.Errorf("create server log: %w", err)
	}

	cmd := exec.CommandContext(ctx, cleaveBin, args...)
	cmd.Stderr = logFile
	cmd.Stdout = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		os.Remove(logFile.Name())
		return nil, fmt.Errorf("start cleave: %w", err)
	}

	s := &cleaveServer{
		cmd:     cmd,
		logFile: logFile,
		port:    port,
		baseURL: fmt.Sprintf("http://127.0.0.1:%d", port),
		client:  &http.Client{Timeout: 10 * time.Minute},
	}

	fmt.Fprintf(os.Stderr, "Started cleave server on %s (PID %d)\n", bind, cmd.Process.Pid)
	fmt.Fprintf(os.Stderr, "Server log: %s\n", logFile.Name())

	if err := waitHealthy(ctx, s.baseURL, 3*time.Minute); err != nil {
		s.stop()
		return nil, fmt.Errorf("server not ready: %w", err)
	}

	return s, nil
}

// waitHealthy polls /health until the server responds 200.
func waitHealthy(ctx context.Context, baseURL string, timeout time.Duration) error {
	client := &http.Client{Timeout: 2 * time.Second}
	healthURL := baseURL + "/health"

	deadline := time.After(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout after %s waiting for %s", timeout, healthURL)
		case <-ticker.C:
			resp, err := client.Get(healthURL)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				fmt.Fprintf(os.Stderr, "Server healthy\n")
				return nil
			}
		}
	}
}

// stop terminates the server process.
func (s *cleaveServer) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "Stopping cleave server (PID %d)\n", s.cmd.Process.Pid)
	s.cmd.Process.Kill()
	s.cmd.Wait()
	if s.logFile != nil {
		s.logFile.Close()
		fmt.Fprintf(os.Stderr, "Server log saved: %s\n", s.logFile.Name())
	}
}
