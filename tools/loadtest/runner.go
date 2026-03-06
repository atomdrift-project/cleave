package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	startedAt     time.Time
	finishedAt    time.Time
	latency       time.Duration
	statusCode    int
	uploadBytes   int64
	responseBytes int64
	err           error
	filename      string
	responseBody  string // populated on non-2xx or error
}

// run executes the load test and returns all results.
func run(ctx context.Context, cfg config, payloads []payload) []result {
	deadline, cancel := context.WithTimeout(ctx, cfg.duration)
	defer cancel()

	var (
		mu      sync.Mutex
		results []result
		idx     atomic.Int64
		maxReqs = int64(cfg.requests) // 0 = unlimited
	)

	// Rate limiter: token bucket via ticker.
	var limiter <-chan time.Time
	if cfg.rps > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(cfg.rps))
		defer ticker.Stop()
		limiter = ticker.C
	}

	client := &http.Client{
		Timeout: 5 * time.Minute,
	}

	var wg sync.WaitGroup
	for range cfg.concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				// Check deadline.
				select {
				case <-deadline.Done():
					return
				default:
				}

				// Rate limit.
				if limiter != nil {
					select {
					case <-limiter:
					case <-deadline.Done():
						return
					}
				}

				// Pick payload; stop if request limit reached.
				i := idx.Add(1) - 1
				if maxReqs > 0 && i >= maxReqs {
					return
				}
				p := payloads[int(i)%len(payloads)]

				// In uncached mode, mutate the payload for each request.
				if cfg.mode == "uncached" {
					p = mutatePayload(p, i)
				}

				r := sendRequest(ctx, client, cfg, p)
				r.filename = p.filename

				if cfg.verbose {
					status := fmt.Sprintf("%d", r.statusCode)
					if r.err != nil {
						status = r.err.Error()
					}
					fmt.Fprintf(os.Stderr, "[%d] %s %s %s\n", i, p.filename, r.latency, status)
				}

				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results
}

// sendRequest uploads a single payload to /analyze.
func sendRequest(ctx context.Context, client *http.Client, cfg config, p payload) result {
	start := time.Now()
	r := result{startedAt: start}

	// Build multipart body.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", p.filename)
	if err != nil {
		r.err = fmt.Errorf("create form file: %w", err)
		r.finishedAt = time.Now()
		r.latency = r.finishedAt.Sub(start)
		return r
	}
	if _, err := part.Write(p.data); err != nil {
		r.err = fmt.Errorf("write payload: %w", err)
		r.finishedAt = time.Now()
		r.latency = r.finishedAt.Sub(start)
		return r
	}
	writer.Close()

	r.uploadBytes = int64(len(p.data))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.server+"/analyze", &body)
	if err != nil {
		r.err = fmt.Errorf("new request: %w", err)
		r.finishedAt = time.Now()
		r.latency = r.finishedAt.Sub(start)
		return r
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		r.err = err
		r.finishedAt = time.Now()
		r.latency = r.finishedAt.Sub(start)
		return r
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	r.statusCode = resp.StatusCode
	r.responseBytes = int64(len(respBody))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || len(respBody) < 256 {
		r.responseBody = truncate(string(respBody), 200)
	}
	r.finishedAt = time.Now()
	r.latency = r.finishedAt.Sub(start)
	return r
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
