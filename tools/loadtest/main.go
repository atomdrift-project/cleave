// loadtest stress-tests a cleave server, measuring QPS, latency, and error rates.
//
// Two modes:
//   - cached:   sends the same files repeatedly (measures cache-hit throughput)
//   - uncached: mutates files per-request to defeat SHA256 cache (measures real analysis throughput)
package main

import (
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"
)

type config struct {
	server      string
	mode        string
	concurrency int
	duration    time.Duration
	requests    int
	rps         int
	payloadDir  string
	verbose     bool
	startServer bool
	cleaveBin   string
}

func main() {
	var cfg config
	flag.StringVar(&cfg.server, "server", "http://127.0.0.1:8080", "target server URL")
	flag.StringVar(&cfg.mode, "mode", "cached", "workload: cached or uncached")
	flag.IntVar(&cfg.concurrency, "concurrency", 10, "parallel workers")
	flag.DurationVar(&cfg.duration, "duration", 30*time.Second, "test duration")
	flag.IntVar(&cfg.requests, "requests", 0, "total requests to send (0 = unlimited, use duration)")
	flag.IntVar(&cfg.rps, "rps", 0, "rate limit (0 = unlimited)")
	flag.StringVar(&cfg.payloadDir, "payload-dir", "", "directory of files to upload (overrides built-in payloads)")
	flag.BoolVar(&cfg.verbose, "verbose", false, "print per-request details")
	flag.BoolVar(&cfg.startServer, "start-server", false, "auto-start cleave server")
	flag.StringVar(&cfg.cleaveBin, "cleave-bin", "", "path to cleave binary (default: find in PATH or build)")
	flag.Parse()

	if cfg.mode != "cached" && cfg.mode != "uncached" {
		fmt.Fprintf(os.Stderr, "error: --mode must be 'cached' or 'uncached', got %q\n", cfg.mode)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Auto-start server if requested.
	var serverLogPath string
	if cfg.startServer {
		srv, err := startServer(ctx, cfg.cleaveBin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to start server: %v\n", err)
			os.Exit(1)
		}
		defer srv.stop()
		cfg.server = srv.baseURL
		if srv.logFile != nil {
			serverLogPath = srv.logFile.Name()
		}
	}

	// Verify server is reachable.
	if err := waitHealthy(ctx, cfg.server, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "error: server not reachable at %s: %v\n", cfg.server, err)
		os.Exit(1)
	}

	// Build payloads.
	payloads, err := buildPayloads(cfg.mode, cfg.payloadDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to build payloads: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded %d payload(s), mode=%s\n", len(payloads), cfg.mode)

	// Run the load test.
	fmt.Fprintf(os.Stderr, "Starting load test: concurrency=%d duration=%s rps=%d\n",
		cfg.concurrency, cfg.duration, cfg.rps)

	results := run(ctx, cfg, payloads)
	printResults(cfg, results, serverLogPath)
}

func printResults(cfg config, results []result, serverLogPath string) {
	if len(results) == 0 {
		fmt.Println("No results collected.")
		return
	}

	var (
		success      int
		failed       int
		err429       int
		err503       int
		errTimeout   int
		errOther     int
		shortResults int
		totalBytes   int64
		totalResp    int64
	)

	latencies := make([]time.Duration, 0, len(results))

	for _, r := range results {
		if r.err != nil {
			failed++
			if strings.Contains(r.err.Error(), "timeout") {
				errTimeout++
			} else {
				errOther++
			}
			continue
		}
		switch {
		case r.statusCode >= 200 && r.statusCode < 300:
			success++
			if r.responseBytes < 256 {
				shortResults++
			}
		case r.statusCode == 429:
			failed++
			err429++
		case r.statusCode == 503:
			failed++
			err503++
		default:
			failed++
			errOther++
		}
		latencies = append(latencies, r.latency)
		totalBytes += r.uploadBytes
		totalResp += r.responseBytes
	}

	total := len(results)
	elapsed := results[len(results)-1].finishedAt.Sub(results[0].startedAt)
	if elapsed == 0 {
		elapsed = 1 * time.Millisecond
	}

	qps := float64(total) / elapsed.Seconds()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Println()
	fmt.Println("── Cleave Load Test Results ──────────────────────")
	fmt.Printf("Mode:          %s\n", cfg.mode)
	fmt.Printf("Duration:      %.1fs\n", elapsed.Seconds())
	fmt.Printf("Concurrency:   %d\n", cfg.concurrency)
	fmt.Printf("Total:         %d requests\n", total)
	fmt.Printf("Success:       %d (%.1f%%)\n", success, pct(success, total))
	fmt.Printf("Failed:        %d (%.1f%%)\n", failed, pct(failed, total))
	if err429 > 0 {
		fmt.Printf("  429 rate-limited:  %d\n", err429)
	}
	if err503 > 0 {
		fmt.Printf("  503 overloaded:    %d\n", err503)
	}
	if errTimeout > 0 {
		fmt.Printf("  timeout:           %d\n", errTimeout)
	}
	if errOther > 0 {
		fmt.Printf("  other:             %d\n", errOther)
	}
	fmt.Printf("QPS:           %.1f\n", qps)

	if len(latencies) > 0 {
		fmt.Println("Latency:")
		fmt.Printf("  min:    %s\n", fmtDuration(latencies[0]))
		fmt.Printf("  p50:    %s\n", fmtDuration(percentile(latencies, 50)))
		fmt.Printf("  p90:    %s\n", fmtDuration(percentile(latencies, 90)))
		fmt.Printf("  p95:    %s\n", fmtDuration(percentile(latencies, 95)))
		fmt.Printf("  p99:    %s\n", fmtDuration(percentile(latencies, 99)))
		fmt.Printf("  max:    %s\n", fmtDuration(latencies[len(latencies)-1]))
	}

	uploadMBps := float64(totalBytes) / 1024 / 1024 / elapsed.Seconds()
	avgResp := float64(totalResp) / float64(max(success, 1))
	fmt.Printf("Upload:        %.1f MB/s\n", uploadMBps)
	fmt.Printf("Avg response:  %.1f KB\n", avgResp/1024)
	fmt.Println("──────────────────────────────────────────────────")

	// Print error and short-response details.
	hasProblems := failed > 0 || shortResults > 0
	if hasProblems {
		fmt.Println()
		fmt.Println("── Errors ───────────────────────────────────────")
		for _, r := range results {
			if r.err != nil {
				fmt.Printf("  %s  %s  err=%s\n",
					r.finishedAt.Format("15:04:05.000"), r.filename, r.err)
			} else if r.statusCode < 200 || r.statusCode >= 300 {
				fmt.Printf("  %s  %s  status=%d  %s\n",
					r.finishedAt.Format("15:04:05.000"), r.filename, r.statusCode, r.responseBody)
			} else if r.responseBytes < 256 {
				fmt.Printf("  %s  %s  short response (%d bytes): %s\n",
					r.finishedAt.Format("15:04:05.000"), r.filename, r.responseBytes, r.responseBody)
			}
		}
		fmt.Println("─────────────────────────────────────────────────")
	}

	if serverLogPath != "" {
		fmt.Printf("\nServer log: %s\n", serverLogPath)
	}
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func fmtDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
