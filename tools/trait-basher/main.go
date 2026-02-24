// trait-basher orchestrates AI to tune cleave trait definitions.
//
// It scans a directory with cleave and invokes an AI assistant (Claude, Gemini,
// Codex, or Opencode) to analyze findings and modify/create traits as needed.
// Providers are tried in order; if one fails (e.g., quota exceeded), the next is tried.
//
// Usage:
//
//	trait-basher --dir /path/to/good-samples --good
//	trait-basher --dir /path/to/malware-samples --bad
//	trait-basher --dir /path/to/samples --bad --provider gemini,claude
//	trait-basher --dir /path/to/samples --bad --provider codex
package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	// validatedProviders tracks which providers have been successfully validated.
	validatedProviders   = make(map[string]bool)
	validatedProvidersMu sync.Mutex
)

// dataDir returns ~/data/<subdir> directory, creating it if needed.
func dataDir(subdir string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, "data", subdir)
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // data dirs need user readability
		return "", err
	}
	return dir, nil
}

// misclassificationMarkerPath returns the path to a misclassification marker file.
// markerType should be "BENIGN" or "BAD".
func misclassificationMarkerPath(filePath, markerType string) string {
	dir := filepath.Dir(filePath)
	base := filepath.Base(filePath)
	return filepath.Join(dir, "._"+base+"."+markerType)
}

// hasMisclassificationMarker checks if a misclassification marker exists.
func hasMisclassificationMarker(filePath string) (found bool, markerType string) {
	benignPath := misclassificationMarkerPath(filePath, "BENIGN")
	badPath := misclassificationMarkerPath(filePath, "BAD")

	if _, err := os.Stat(benignPath); err == nil {
		return true, "BENIGN"
	}
	if _, err := os.Stat(badPath); err == nil {
		return true, "BAD"
	}
	return false, ""
}

// reviewCoordinator manages concurrent LLM review sessions.
type reviewCoordinator struct {
	jobs    chan reviewJob
	results chan reviewResult
	cfg     *config
	logger  *slog.Logger
	workers []workerState
	wg      sync.WaitGroup
	mu      sync.Mutex
}

// newReviewCoordinator creates a coordinator with N worker goroutines.
func newReviewCoordinator(ctx context.Context, cfg *config, logger *slog.Logger) *reviewCoordinator {
	now := time.Now()
	workers := make([]workerState, cfg.concurrency)
	for i := range workers {
		workers[i] = workerState{busy: false, startTime: now}
	}

	rc := &reviewCoordinator{
		jobs:    make(chan reviewJob, cfg.concurrency*2), // buffer for scan-ahead
		results: make(chan reviewResult, cfg.concurrency*2),
		cfg:     cfg,
		logger:  logger,
		workers: workers,
	}

	// Start worker goroutines
	for i := range cfg.concurrency {
		rc.wg.Add(1)
		go rc.worker(ctx, i)
	}

	return rc
}

// submit sends a job for review. Blocks if buffer is full (backpressure).
func (rc *reviewCoordinator) submit(job reviewJob) {
	rc.jobs <- job
}

// close signals no more jobs and waits for all workers to finish.
func (rc *reviewCoordinator) close() {
	close(rc.jobs)
	rc.wg.Wait()
	close(rc.results)
}

// activeCount returns the number of reviews currently in progress.
func (rc *reviewCoordinator) activeCount() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	count := 0
	for _, w := range rc.workers {
		if w.busy {
			count++
		}
	}
	return count
}

// slotStatus returns a slice of status lines, one per worker slot.
// Example lines: "  [1] claude: /path/to/file.sh (2m30s)" or "  [2] idle (45s)"
// Validation samples show "🔍" prefix to distinguish from real exceptions.
func (rc *reviewCoordinator) slotStatus() []string {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	lines := make([]string, len(rc.workers))
	for i, w := range rc.workers {
		dur := time.Since(w.startTime).Round(time.Second)
		if w.busy {
			pClr := providerColor(w.provider)
			prefix := ""
			if w.isValidation {
				prefix = "🔍 "
			}
			lines[i] = fmt.Sprintf("  %s[%d]%s %s%s%s: %s%s %s(%v)%s",
				colorDim, i+1, colorReset,
				pClr, w.provider, colorReset,
				prefix, w.path,
				colorDim, dur, colorReset)
		} else {
			lines[i] = fmt.Sprintf("  %s[%d] idle (%v)%s", colorDim, i+1, dur, colorReset)
		}
	}
	return lines
}

// setWorkerBusy marks a worker as busy with a job.
func (rc *reviewCoordinator) setWorkerBusy(workerID int, path, provider string, isValidation bool) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.workers[workerID] = workerState{
		busy:         true,
		path:         path,
		provider:     provider,
		isValidation: isValidation,
		startTime:    time.Now(),
	}
}

// setWorkerIdle marks a worker as idle.
func (rc *reviewCoordinator) setWorkerIdle(workerID int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.workers[workerID] = workerState{
		busy:      false,
		startTime: time.Now(),
	}
}

// workerPrefix returns a colored prefix for LLM output lines: "🟡 filename         │ ".
func (rc *reviewCoordinator) workerPrefix(workerID int) string {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	w := rc.workers[workerID]
	name := filepath.Base(w.path)
	if len(name) > 16 {
		name = name[:16]
	}
	pClr := providerColor(w.provider)
	emoji := workerEmoji(workerID)
	return fmt.Sprintf("%s %s%-16s%s │ ", emoji, pClr, name, colorReset)
}

func (rc *reviewCoordinator) worker(ctx context.Context, id int) {
	defer rc.wg.Done()

	for job := range rc.jobs {
		path := jobPath(job)

		// Create a per-job config copy to avoid race conditions on cfg.provider
		jobCfg := *rc.cfg
		jobCfg.provider = rc.cfg.providers[0]

		// Track worker as busy
		rc.setWorkerBusy(id, path, jobCfg.provider, job.isValidation)

		start := time.Now()
		var err error

		// Retry loop with exponential backoff
		const maxRetries = 10
		for attempt := 1; attempt <= maxRetries; attempt++ {
			// Generate fresh session ID for each attempt to avoid "session already in use" errors
			sid := generateSessionID()

			// Update provider in worker state
			rc.mu.Lock()
			rc.workers[id].provider = jobCfg.provider
			rc.mu.Unlock()
			if job.archive != nil {
				err = invokeAIArchive(ctx, &jobCfg, job.archive, job.isValidation, sid, id, rc)
			} else if job.file != nil {
				err = rc.reviewFile(ctx, &jobCfg, job.file, job.isValidation, sid, id)
			}

			if err == nil {
				break // Success
			}

			if attempt == maxRetries {
				break // Give up after max retries
			}

			// Log retry and backoff
			delay := retryDelay()
			if rc.logger != nil {
				rc.logger.Warn("review_retry",
					"path", path,
					"attempt", attempt,
					"error", err.Error(),
					"delay", delay,
				)
			}
			fmt.Fprintf(os.Stderr, "\n%s⚠️  Review failed for %s:%s %v %s(attempt %d/%d, retrying in %v)%s\n",
				colorYellow, filepath.Base(path), colorReset, err, colorDim, attempt, maxRetries, delay.Round(time.Second), colorReset)
			time.Sleep(delay)
		}

		// Mark worker as idle
		rc.setWorkerIdle(id)

		rc.results <- reviewResult{
			job:      job,
			err:      err,
			duration: time.Since(start),
			provider: jobCfg.provider,
		}
	}
}

func jobPath(job reviewJob) string {
	if job.archive != nil {
		return job.archive.ArchivePath
	}
	if job.file != nil {
		return job.file.RealPath
	}
	return ""
}

func (rc *reviewCoordinator) reviewFile(ctx context.Context, cfg *config, file *RealFileAnalysis, isValidation bool, sid string, workerID int) error {
	// Aggregate findings from root and all fragments
	agg := file.Root
	if agg.Path == "" {
		agg.Path = file.RealPath
	}
	for _, frag := range file.Fragments {
		agg.Findings = append(agg.Findings, frag.Findings...)
	}

	return invokeAI(ctx, cfg, agg, isValidation, sid, workerID, rc)
}

const maxYAMLAutoFixAttempts = 3

// geminiDefaultModels is the ordered list of Gemini models to try when no model is specified.
// Falls back through these when quota is exhausted or errors occur.
var geminiDefaultModels = []string{
	"gemini-3-pro-preview",
	"gemini-3-flash-preview",
	"gemini-2.5-pro",
	"gemini-2.5-flash",
}

// archiveNeedsReview returns true if the archive needs review.
// Returns (needsReview, isValidationSample).
// Uses the archive summary findings when available (from cleave's aggregated output).
// For known-good archives: review if ANY hostile OR 2+ suspicious (to reduce false positives).
//
//	Up to 1 suspicious finding is acceptable.
//
// For known-bad archives: review if NOT flagged (missing detections).
func archiveNeedsReview(a *ArchiveAnalysis, knownGood bool, validateEvery int) (review bool, isValidation bool) {
	// Use summary findings if available (preferred - avoids race conditions from parallel streaming)
	if len(a.SummaryFindings) > 0 || a.SummaryRisk != "" {
		// Create aggregate FileAnalysis from summary to reuse needsReview logic
		agg := FileAnalysis{
			Path:     a.ArchivePath,
			Risk:     a.SummaryRisk,
			Findings: a.SummaryFindings,
		}
		return needsReview(agg, knownGood, validateEvery)
	}

	// Fallback to member-based logic (legacy behavior, shouldn't happen with new cleave)
	// Aggregate all member findings for accurate threshold checking
	agg := FileAnalysis{Path: a.ArchivePath}
	for _, m := range a.Members {
		agg.Findings = append(agg.Findings, m.Findings...)
	}
	return needsReview(agg, knownGood, validateEvery)
}

// archiveProblematicMembers returns members that individually meet the review threshold.
// Note: This is used for prioritizing files to show the AI, not for the review decision
// (which is based on aggregate findings across all members).
func archiveProblematicMembers(a *ArchiveAnalysis, knownGood bool) []FileAnalysis {
	var result []FileAnalysis
	for _, m := range a.Members {
		// For member selection, we don't use validation sampling - just normal thresholds
		if review, _ := needsReview(m, knownGood, 0); review {
			result = append(result, m)
		}
	}
	return result
}

func main() {
	log.SetFlags(0)

	knownGood := flag.Bool("good", false, "Review known-good files for false positives (suspicious/hostile findings)")
	knownBad := flag.Bool("bad", false, "Review known-bad files for false negatives (missing detections)")
	provider := flag.String("provider", "gemini,codex,claude,opencode", "AI providers (comma-separated, tries in order on failure)")
	model := flag.String("model", "", `Model to use (provider-specific). If not set, gemini
auto-tries models in order: gemini-3-pro-preview, gemini-3-flash-preview,
gemini-2.5-pro, gemini-2.5-flash. Popular choices:
  claude:   sonnet, opus, haiku
  gemini:   gemini-3-pro-preview, gemini-3-flash-preview,
            gemini-2.5-pro, gemini-2.5-flash, gemini-2.5-flash-lite
  codex:    gpt-5-codex, gpt-5-codex-mini, gpt-5
  opencode: gpt-4.1, gpt-4.1-mini, o4-mini, o3, moonshotai/kimi-k2.5`)
	repoRoot := flag.String("repo-root", "", "Path to cleave repo root (auto-detected if not specified)")
	useCargo := flag.Bool("cargo", true, "Use 'cargo run --release' instead of cleave binary")
	timeout := flag.Duration("timeout", 20*time.Minute, "Maximum time for each AI invocation")
	idleTimeout := flag.Duration("idle-timeout", 8*time.Minute, "Kill LLM if no output for this duration")
	flush := flag.Bool("flush", false, "Clear analysis cache and reprocess all files")
	rescanAfter := flag.Int("rescan-after", 4, "Restart scan after reviewing N files to verify fixes (0 = disabled)")
	concurrency := flag.Int("concurrency", 2, "Number of concurrent LLM review sessions")
	verbose := flag.Bool("verbose", false, "Show detailed skip/progress messages")
	validateEvery := flag.Int("validate-every", 500, "Randomly validate 1 in N files even if properly classified (0 = disabled)")
	trainingDir := flag.String("training-dir", "", "Root directory for saving training JSONL (creates good/, bad/, good-review/, bad-review/ subdirs)")

	flag.Parse()

	if *concurrency < 1 {
		log.Fatal("--concurrency must be at least 1")
	}

	dirs := flag.Args()
	if len(dirs) == 0 {
		log.Fatal("At least one directory is required as an argument")
	}
	for _, dir := range dirs {
		if info, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				log.Fatalf("Directory does not exist: %s", dir)
			}
			log.Fatalf("Cannot access directory %s: %v", dir, err)
		} else if !info.IsDir() {
			log.Fatalf("Not a directory: %s", dir)
		}
	}
	if !*knownGood && !*knownBad {
		log.Fatal("Either --good or --bad is required")
	}
	if *knownGood && *knownBad {
		log.Fatal("Cannot specify both --good and --bad")
	}

	// Parse and validate provider list
	var providers []string
	for p := range strings.SplitSeq(*provider, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		// Allow provider:model syntax (e.g., gemini:gemini-2.5-pro)
		base := p
		if idx := strings.Index(p, ":"); idx != -1 {
			base = p[:idx]
		}
		if base != "claude" && base != "gemini" && base != "codex" && base != "opencode" {
			log.Fatalf("Unknown provider %q: must be claude, gemini, codex, or opencode", base)
		}
		providers = append(providers, p)
	}
	if len(providers) == 0 {
		log.Fatal("At least one provider must be specified")
	}

	// Expand bare "gemini" into model-specific entries for automatic fallback
	// Only expand if no explicit --model is set
	if *model == "" {
		var expanded []string
		for _, p := range providers {
			if p == "gemini" {
				// Expand to try each default model in order
				for _, m := range geminiDefaultModels {
					expanded = append(expanded, "gemini:"+m)
				}
			} else {
				expanded = append(expanded, p)
			}
		}
		providers = expanded
	}

	// Find repo root (for running cleave via cargo).
	resolvedRoot := *repoRoot
	if resolvedRoot == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
		cancel()
		if err != nil {
			log.Fatalf("Could not detect repo root: %v. Use --repo-root flag.", err)
		}
		resolvedRoot = strings.TrimSpace(string(out))
	}

	// Load prompt template
	if err := loadPromptTemplate(resolvedRoot); err != nil {
		log.Fatalf("Could not load prompt template: %v", err)
	}

	db, err := openDB(context.Background(), *flush)
	if err != nil {
		log.Fatalf("Could not open database: %v", err)
	}

	// Clean up orphaned extract directories from crashed/killed previous runs.
	cleanupOrphanedExtractDirs()

	// Create temp directory for extracted samples with PID for easier debugging.
	// cleave writes files to <extract-dir>/<sha256[0:6]>/<relative-path>.
	// Directory persists across rescans for cache reuse.
	extractDir := filepath.Join(os.TempDir(), fmt.Sprintf("tbsh.%d", os.Getpid()))
	if err := os.MkdirAll(extractDir, 0o750); err != nil {
		db.Close() //nolint:errcheck,gosec // best-effort cleanup on fatal error
		log.Fatalf("Could not create extract directory: %v", err)
	}

	// Set up signal handler for cleanup on interrupt/termination.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n%sInterrupted.%s Cleaning up %s...\n", colorYellow, colorReset, extractDir)
		os.RemoveAll(extractDir) //nolint:errcheck,gosec // best-effort cleanup on signal
		db.Close()               //nolint:errcheck,gosec // best-effort cleanup on signal
		os.Exit(1)
	}()

	defer os.RemoveAll(extractDir) //nolint:errcheck // best-effort cleanup
	defer db.Close()               //nolint:errcheck // best-effort cleanup

	// Set up training data directories if --training-dir is specified
	// - Confirmed files → <training-dir>/good or <training-dir>/bad
	// - Files needing review → <training-dir>/good-review or <training-dir>/bad-review
	var trainingDataDir, trainingReviewDir string
	if *trainingDir != "" {
		subdir := "bad"
		reviewSubdir := "bad-review"
		if *knownGood {
			subdir = "good"
			reviewSubdir = "good-review"
		}
		trainingDataDir = filepath.Join(*trainingDir, subdir)
		trainingReviewDir = filepath.Join(*trainingDir, reviewSubdir)
		if err := os.MkdirAll(trainingDataDir, 0o755); err != nil {
			log.Fatalf("Could not create training data directory %s: %v", trainingDataDir, err)
		}
		if err := os.MkdirAll(trainingReviewDir, 0o755); err != nil {
			log.Fatalf("Could not create training review directory %s: %v", trainingReviewDir, err)
		}
		fmt.Fprintf(os.Stderr, "%sTraining data:%s %s (confirmed), %s (review)\n", colorDim, colorReset, trainingDataDir, trainingReviewDir)
	}

	cfg := &config{
		dirs:              dirs,
		repoRoot:          resolvedRoot,
		providers:         providers,
		provider:          providers[0], // Current active provider
		model:             *model,
		timeout:           *timeout,
		idleTimeout:       *idleTimeout,
		knownGood:         *knownGood,
		knownBad:          *knownBad,
		useCargo:          *useCargo,
		flush:             *flush,
		verbose:           *verbose,
		db:                db,
		extractDir:        extractDir,
		trainingDataDir:   trainingDataDir,
		trainingReviewDir: trainingReviewDir,
		rescanAfter:       *rescanAfter,
		concurrency:       *concurrency,
		validateEvery:     *validateEvery,
	}

	ctx := context.Background()

	// Build or locate cleave binary
	if *useCargo {
		fmt.Fprint(os.Stderr, "Building release binary with cargo build --release...\n")

		cmd := exec.CommandContext(ctx, "cargo", "build", "--release")
		cmd.Dir = resolvedRoot

		var stderr bytes.Buffer
		cmd.Stderr = &stderr

		if err := cmd.Run(); err != nil {
			db.Close()               //nolint:errcheck,gosec // best-effort cleanup before fatal
			os.RemoveAll(extractDir) //nolint:errcheck,gosec // best-effort cleanup before fatal
			//nolint:gocritic // exitAfterDefer is intentional; manual cleanup done above
			log.Fatalf("cargo build --release failed: %v (%s)", err, stderr.String())
		}

		// Determine binary path based on OS
		binName := "cleave"
		if runtime.GOOS == "windows" {
			binName = "cleave.exe"
		}
		cfg.cleaveBin = filepath.Join(resolvedRoot, "target", "release", binName)

		// Verify the binary exists
		if _, err := os.Stat(cfg.cleaveBin); err != nil {
			log.Fatalf("binary not found at %s: %v", cfg.cleaveBin, err)
		}

		fmt.Fprintf(os.Stderr, "Built release binary: %s\n", cfg.cleaveBin)
	} else {
		cfg.cleaveBin = "cleave"
	}

	// Sanity check: run cleave on /bin/ls to catch code errors early.
	for attempt := 1; ; attempt++ {
		if err := sanityCheck(ctx, cfg); err != nil {
			if !isYAMLTraitIssue(err.Error()) || attempt > maxYAMLAutoFixAttempts {
				log.Fatalf("Sanity check failed: %v", err)
			}
			if fixErr := invokeYAMLTraitFixer(ctx, cfg, "initial sanity check", err.Error(), attempt, maxYAMLAutoFixAttempts); fixErr != nil {
				log.Fatalf("Sanity check failed: %v (YAML trait auto-fix failed: %v)", err, fixErr)
			}
			fmt.Fprint(os.Stderr, "Waiting 1 second before re-running sanity check...\n")
			time.Sleep(1 * time.Second)
			continue
		}
		break
	}

	mode := "known-bad"
	if cfg.knownGood {
		mode = "known-good"
	}

	// Display providers in a readable format (collapse gemini:model entries)
	displayProviders := formatProvidersForDisplay(cfg.providers)
	if cfg.model != "" {
		fmt.Fprintf(os.Stderr, "%sProviders:%s %s%s%s (model: %s%s%s)\n",
			colorDim, colorReset, colorCyan, displayProviders, colorReset, colorCyan, cfg.model, colorReset)
	} else {
		fmt.Fprintf(os.Stderr, "%sProviders:%s %s%s%s\n", colorDim, colorReset, colorCyan, displayProviders, colorReset)
	}
	modeColor := colorRed
	if cfg.knownGood {
		modeColor = colorGreen
	}
	fmt.Fprintf(os.Stderr, "%sMode:%s %s%s%s\n", colorDim, colorReset, modeColor, mode, colorReset)
	fmt.Fprintf(os.Stderr, "%sRepo root:%s %s\n", colorDim, colorReset, cfg.repoRoot)
	fmt.Fprintf(os.Stderr, "%sLLM timeout:%s %v (session max), %v (idle)\n", colorDim, colorReset, cfg.timeout, cfg.idleTimeout)
	fmt.Fprintf(os.Stderr, "%sConcurrency:%s %s%d%s parallel LLM sessions\n", colorDim, colorReset, colorCyan, cfg.concurrency, colorReset)
	fmt.Fprintf(os.Stderr, "%sStreaming analysis of%s %v...\n\n", colorDim, colorReset, cfg.dirs)

	// Database mode (good/bad, not known-good/known-bad).
	dbMode := "bad"
	if cfg.knownGood {
		dbMode = "good"
	}

	// Track wall clock time for overall run statistics
	sessionStartTime := time.Now()

	// Use streaming analysis - process each archive as it completes.
	// Loop and restart after reviewing N files to catch fixed files.
	yamlFixAttempts := 0
	for {
		// Reset to first provider on each scan iteration so all providers get re-evaluated
		cfg.provider = cfg.providers[0]

		stats, err := streamAnalyzeAndReview(ctx, cfg, dbMode)
		if err != nil {
			if isYAMLTraitIssue(err.Error()) && yamlFixAttempts < maxYAMLAutoFixAttempts {
				yamlFixAttempts++
				errMsg := err.Error()
				fixErr := invokeYAMLTraitFixer(ctx, cfg, "scan/restart loop", errMsg, yamlFixAttempts, maxYAMLAutoFixAttempts)
				if fixErr != nil {
					log.Fatalf("Analysis failed: %v (YAML trait auto-fix failed: %v)", err, fixErr)
				}
				fmt.Fprint(os.Stderr, "Waiting 1 second before restarting scan...\n")
				time.Sleep(1 * time.Second)
				continue
			}
			// For cleave or other errors, retry after delay (already slept in streamAnalyzeAndReview)
			fmt.Fprint(os.Stderr, "Restarting scan after error...\n")
			continue
		}
		yamlFixAttempts = 0

		if !stats.shouldRestart {
			// No more files to review
			wallClockTime := time.Since(sessionStartTime)
			fmt.Fprint(os.Stderr, "\n=== Session Complete ===\n")
			fmt.Fprintf(os.Stderr, "Reviewed: %d archives, %d standalone files\n",
				stats.archivesReviewed, stats.standaloneReviewed)
			fmt.Fprintf(os.Stderr, "Skipped: %d (cached), %d (no review needed)\n",
				stats.skippedCached, stats.skippedNoReview)

			// Calculate review rate for standalone files
			if stats.totalStandaloneFiles > 0 {
				reviewRate := float64(stats.standaloneReviewed) / float64(stats.totalStandaloneFiles) * 100
				fmt.Fprintf(os.Stderr, "Standalone file review rate: %d/%d (%.1f%%)\n",
					stats.standaloneReviewed, stats.totalStandaloneFiles, reviewRate)
			}

			// Show timing statistics
			fmt.Fprintf(os.Stderr, "Wall clock time: %v\n", wallClockTime.Round(time.Second))
			fmt.Fprintf(os.Stderr, "LLM review time: %v\n", stats.reviewTimeTotal.Round(time.Second))
			if wallClockTime > 0 {
				reviewPercent := float64(stats.reviewTimeTotal) / float64(wallClockTime) * 100
				fmt.Fprintf(os.Stderr, "Review time as %% of total: %.1f%%\n", reviewPercent)
			}
			break
		}

		// Restart to verify fixes on the next batch
		fmt.Fprint(os.Stderr, "Waiting 1 second before restarting scan...\n")
		time.Sleep(1 * time.Second)
	}

	fmt.Fprint(os.Stderr, "Run \"git diff traits/\" to see changes.\n")
}

// flushingWriter wraps an io.Writer and flushes after every write to ensure logs survive OOM kills.
type flushingWriter struct {
	w interface {
		io.Writer
		Sync() error
	}
}

func (f *flushingWriter) Write(p []byte) (n int, err error) {
	n, err = f.w.Write(p)
	if err != nil {
		return n, err
	}
	// Flush to disk after every write (performance cost but critical for crash debugging)
	// Use Sync() instead of Flush() to ensure data is committed to storage
	if err := f.w.Sync(); err != nil {
		return n, err
	}
	return n, nil
}

// streamState tracks the current processing state as we stream files.
type streamState struct {
	// time.Time first (24 bytes)
	archiveStartTime time.Time // Track when current archive started processing
	// Pointers and slices (8 bytes each)
	cfg             *config
	stats           *streamStats
	currentArchive  *ArchiveAnalysis
	currentRealFile *RealFileAnalysis
	logger          *slog.Logger
	coordinator     *reviewCoordinator
	// Strings (16 bytes each)
	dbMode             string
	currentArchivePath string
	currentRealPath    string
	currentScanPath    string // Current file being scanned (for progress display)
	// Ints
	filesReviewedCount int // Count of files sent to LLM for review
}

// streamAnalyzeAndReview streams cleave output and reviews archives as they complete.
func streamAnalyzeAndReview(ctx context.Context, cfg *config, dbMode string) (*streamStats, error) {
	// Generate unique session ID early for log file naming and log entries
	sessionID := generateSessionID()
	pid := os.Getpid()

	// Determine log file path for cleave's own logs (session-specific)
	cleaveLogPath, err := getcleaveLogFilePath(sessionID)
	if err != nil {
		return nil, fmt.Errorf("could not determine cleave log path: %w", err)
	}

	// Build cleave command with --extract-dir for file extraction.
	// cleave extracts all analyzed files to <extract-dir>/<sha256>/<relative-path>.
	// Use --max-file-mem 0 to force all extraction to disk (not RAM) to prevent OOM
	// Use --verbose and --log-file to capture comprehensive logs for debugging OOM issues
	// Use --validate=true to enable trait validation (disabled by default in cleave)
	args := []string{
		"--format", "jsonl",
		"--extract-dir", cfg.extractDir,
		"--max-file-mem", "0",
		"--log-file", cleaveLogPath,
		"--validate=true",
		"--shuffle",
	}
	args = append(args, cfg.dirs...)
	cmd := exec.CommandContext(ctx, cfg.cleaveBin, args...) //nolint:gosec // cleaveBin is built from trusted cargo
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("could not create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("could not create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("could not start cleave: %w", err)
	}

	cleavePID := cmd.Process.Pid
	fmt.Fprintf(os.Stderr, "cleave logs: %s (PID %d)\n", cleaveLogPath, cleavePID)

	// Stream cleave stderr to our own stderr in background.
	// Captures relevant lines for error messages when cleave fails.
	stderrCh := make(chan []string, 1)
	go func() {
		var lines []string
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 32*1024*1024), 32*1024*1024) // 32MB for panic backtraces
		for sc.Scan() {
			s := sc.Text()
			if strings.Contains(s, "Periodic memory check") {
				continue
			}
			fmt.Fprintf(os.Stderr, "[cleave:%d] %s\n", cleavePID, s)
			// Capture YAML validation keywords for error detection
			lo := strings.ToLower(s)
			if strings.Contains(lo, "error") || strings.Contains(lo, "yaml") ||
				strings.Contains(lo, "trait") || strings.Contains(lo, "validation") ||
				strings.Contains(lo, "fix") {
				lines = append(lines, s)
				if len(lines) > 100 {
					lines = lines[1:]
				}
			}
		}
		stderrCh <- lines
	}()

	// Set up dual-output logging: structured JSON to disk, human-readable to console
	// Use session-specific log file to avoid conflicts with parallel sessions
	logPath, err := getLogFilePath(sessionID)
	if err != nil {
		return nil, fmt.Errorf("could not determine log path: %w", err)
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // logs need user readability
	if err != nil {
		return nil, fmt.Errorf("could not create log file: %w", err)
	}
	defer logFile.Close() //nolint:errcheck // best-effort cleanup

	// Print log location to stderr so users know where to find it
	fmt.Fprintf(os.Stderr, "Logging to: %s\n", logPath)

	// Wrap log file with flushing writer to ensure logs survive OOM kills
	flushingFile := &flushingWriter{w: logFile}

	// File-only logger for structured debugging (console output is handled directly by fmt)
	fileHandler := slog.NewJSONHandler(flushingFile, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(fileHandler).With(
		"session_id", sessionID,
		"pid", pid,
	)

	// Build full command line for logging (reuse args from above)
	fullCmd := append([]string{cfg.cleaveBin}, args...)

	sessionStart := time.Now()

	// Print session info to stderr for easy identification
	fmt.Fprintf(os.Stderr, "\n=== trait-basher session %s (PID %d) ===\n", sessionID, pid)

	logger.Info("trait-basher session started",
		"cleave_bin", cfg.cleaveBin,
		"cleave_args", strings.Join(args, " "),
		"full_command", strings.Join(fullCmd, " "),
		"dirs", cfg.dirs,
		"provider", cfg.provider,
		"mode", dbMode,
		"repo_root", cfg.repoRoot,
		"use_cargo", cfg.useCargo,
	)

	// Pre-count files for progress estimation
	fmt.Fprint(os.Stderr, "Counting files...")
	estimatedTotal := countFiles(cfg.dirs)
	fmt.Fprintf(os.Stderr, " %d files found\n", estimatedTotal)

	// Create review coordinator for concurrent LLM sessions
	coordinator := newReviewCoordinator(ctx, cfg, logger)

	state := &streamState{
		cfg:    cfg,
		dbMode: dbMode,
		stats: &streamStats{
			estimatedTotal: estimatedTotal,
			scanStartTime:  time.Now(),
		},
		logger:      logger,
		coordinator: coordinator,
	}

	// Result collector goroutine - processes review outcomes
	resultsDone := make(chan struct{})
	go func() {
		defer close(resultsDone)
		for result := range coordinator.results {
			path := jobPath(result.job)
			if result.err != nil {
				logger.Error("review_failed",
					"path", path,
					"error", result.err.Error(),
					"duration", result.duration,
					"provider", result.provider,
				)
				continue
			}

			// Update stats
			state.stats.mu.Lock()
			state.stats.reviewTimeTotal += result.duration
			if result.job.archive != nil {
				state.stats.archivesReviewed++
				// Mark as analyzed in cache
				archiveHash := hashString(result.job.archive.ArchivePath)
				if err := markAnalyzed(ctx, cfg.db, archiveHash, dbMode); err != nil {
					logger.Warn("failed to mark analyzed", "path", path, "error", err)
				}
			} else {
				state.stats.standaloneReviewed++
				// Mark as analyzed in cache
				h, err := hashFile(result.job.file.RealPath)
				if err != nil {
					h = hashString(result.job.file.RealPath)
				}
				if err := markAnalyzed(ctx, cfg.db, h, dbMode); err != nil {
					logger.Warn("failed to mark analyzed", "path", path, "error", err)
				}
			}
			// Only count non-validation reviews toward rescan threshold
			// Validation samples are random audits that shouldn't trigger rescans
			if !result.job.isValidation {
				state.filesReviewedCount++

				// Check rescan threshold
				if cfg.rescanAfter > 0 && state.filesReviewedCount >= cfg.rescanAfter {
					state.stats.shouldRestart = true
				}
			}
			state.stats.mu.Unlock()

			logger.Info("review_completed",
				"path", path,
				"duration", result.duration,
				"provider", result.provider,
			)
		}
	}()

	// Log session end with final statistics
	defer func() {
		logger.Info("trait-basher session ended",
			"duration_seconds", time.Since(sessionStart).Seconds(),
			"total_files", state.stats.totalFiles,
			"archives_reviewed", state.stats.archivesReviewed,
			"skipped_cached", state.stats.skippedCached,
			"skipped_no_review", state.stats.skippedNoReview,
		)
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 128*1024*1024), 128*1024*1024) // 128MB buffer

	fileCount := 0
	last := time.Now()
	progressLines := 0 // tracks multi-line progress display for proper clearing

	for scanner.Scan() {
		// Check if we need to restart (hit review limit)
		if state.stats.shouldRestart {
			clearProgressLine()
			fmt.Fprintf(os.Stderr, "%s⚡%s Reviewed %s%d%s files - restarting scan to verify trait changes (killing cleave)\n",
				colorYellow, colorReset, colorBold, state.cfg.rescanAfter, colorReset)
			cmd.Process.Kill() //nolint:errcheck,gosec // intentional kill on restart
			cmd.Wait()         //nolint:errcheck,gosec // reap the process
			return state.stats, nil
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry jsonlEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.Type != "file" {
			continue
		}

		// Cap finding descriptions at 256 characters to prevent output explosion.
		// Final length will be 259 chars (256 + "...") when truncated.
		for i := range entry.Findings {
			if len(entry.Findings[i].Desc) > 256 {
				entry.Findings[i].Desc = entry.Findings[i].Desc[:256] + "..."
			}
		}

		fileCount++
		state.currentScanPath = entry.Path

		// Update progress display periodically
		if time.Since(last) > 100*time.Millisecond {
			elapsed := time.Since(state.stats.scanStartTime).Seconds()
			filesPerSec := 0.0
			if elapsed > 0 {
				filesPerSec = float64(fileCount) / elapsed
			}

			// Calculate detection rate (correct classifications)
			// For --bad: skippedNoReview = detected (TP), reviewed = missed (FN)
			// For --good: skippedNoReview = clean (TN), reviewed = false alarm (FP)
			state.stats.mu.Lock()
			totalProcessed := state.stats.skippedNoReview + state.stats.archivesReviewed + state.stats.standaloneReviewed
			state.stats.mu.Unlock()
			detectionRate := 0.0
			if totalProcessed > 0 {
				detectionRate = float64(state.stats.skippedNoReview) / float64(totalProcessed) * 100
			}

			// Get slot status for progress display
			slotLines := coordinator.slotStatus()

			progress := formatProgress(fileCount, state.stats.estimatedTotal, detectionRate, filesPerSec, entry.Path, cfg.knownGood)

			// Clear previous progress lines (1 main + N slots) and print new ones
			totalLines := 1 + len(slotLines)
			if progressLines > 0 {
				// Move cursor up and clear each line
				fmt.Fprintf(os.Stderr, "\033[%dA", progressLines)
			}
			fmt.Fprintf(os.Stderr, "\033[K%s\n", progress)
			for _, line := range slotLines {
				fmt.Fprintf(os.Stderr, "\033[K%s\n", line)
			}
			progressLines = totalLines
			last = time.Now()
		}

		f := FileAnalysis{
			Path:          entry.Path,
			Risk:          entry.Risk,
			Findings:      entry.Findings,
			ExtractedPath: entry.ExtractedPath,
			RawJSONL:      line, // Preserve for training data
		}

		// Extract archive path from "archive.zip!!inner/file.py" format
		ap := ""
		if idx := strings.Index(f.Path, "!!"); idx != -1 {
			ap = f.Path[:idx]
		}
		processFileEntry(ctx, state, f, ap)
	}

	if state.currentRealFile != nil {
		clearProgressLine()
		processRealFile(ctx, state)
	}
	if state.currentArchive != nil {
		clearProgressLine()
		processCompletedArchive(ctx, state)
	}

	// Close coordinator and wait for all reviews to complete
	clearProgressLine()
	if activeCount := coordinator.activeCount(); activeCount > 0 {
		fmt.Fprintf(os.Stderr, "%s✓%s Scan complete. Waiting for %s%d%s active review(s) to finish...\n",
			colorGreen, colorReset, colorYellow, activeCount, colorReset)
	}
	coordinator.close()
	<-resultsDone

	if err := scanner.Err(); err != nil {
		// Kill orphaned cleave process before returning
		log.Print("killing cleave...")
		cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill on error, process may already be dead
		cmd.Wait()         //nolint:errcheck,gosec // reap the process, error doesn't matter
		delay := retryDelay()
		fmt.Fprintf(os.Stderr, "\n%s⚠️  Error reading cleave output:%s %v\n", colorYellow, colorReset, err)
		fmt.Fprintf(os.Stderr, "   %sRetrying in %v...%s\n", colorDim, delay.Round(time.Second), colorReset)
		time.Sleep(delay)
		return state.stats, fmt.Errorf("error reading cleave output: %w (will retry)", err)
	}

	if err := cmd.Wait(); err != nil {
		delay := retryDelay()
		fmt.Fprintf(os.Stderr, "\n%s⚠️  cleave failed:%s %v (check cleave logs for details)\n", colorYellow, colorReset, err)
		fmt.Fprintf(os.Stderr, "   %sRetrying in %v...%s\n", colorDim, delay.Round(time.Second), colorReset)
		time.Sleep(delay)
		// Include captured stderr for YAML issue detection
		if lines := <-stderrCh; len(lines) > 0 {
			return state.stats, fmt.Errorf("cleave failed: %w\n%s", err, strings.Join(lines, "\n"))
		}
		return state.stats, fmt.Errorf("cleave failed: %w (will retry)", err)
	}

	// Final scan summary
	clearProgressLine()
	elapsed := time.Since(state.stats.scanStartTime).Seconds()
	filesPerSec := 0.0
	if elapsed > 0 {
		filesPerSec = float64(fileCount) / elapsed
	}
	state.stats.mu.Lock()
	totalProcessed := state.stats.skippedNoReview + state.stats.archivesReviewed + state.stats.standaloneReviewed
	reviewed := state.stats.archivesReviewed + state.stats.standaloneReviewed
	skipped := state.stats.skippedNoReview + state.stats.skippedCached
	state.stats.mu.Unlock()
	detectionRate := 0.0
	if totalProcessed > 0 {
		detectionRate = float64(state.stats.skippedNoReview) / float64(totalProcessed) * 100
	}
	rateLabel := "Det"
	if cfg.knownGood {
		rateLabel = "Clean"
	}
	rateClr := rateColor(detectionRate)
	fmt.Fprintf(os.Stderr, "%s✓%s Scanned %s%d%s files in %.1fs (%s%.0f/s%s) | %s%s:%.0f%%%s | Reviewed:%s%d%s Skipped:%s%d%s\n",
		colorGreen, colorReset,
		colorBold, fileCount, colorReset,
		elapsed,
		colorCyan, filesPerSec, colorReset,
		rateClr, rateLabel, detectionRate, colorReset,
		colorYellow, reviewed, colorReset,
		colorDim, skipped, colorReset)
	return state.stats, nil
}

func processFileEntry(ctx context.Context, st *streamState, f FileAnalysis, ap string) {
	switch {
	case ap == "" && st.currentArchivePath != "" && f.Path == st.currentArchivePath:
		// Archive summary entry - cleave now emits this after all member files
		// It contains aggregated risk/findings from all members, so we use it directly
		// instead of computing from members (which may have arrived out of order)
		if st.currentArchive != nil {
			// Update the archive with the summary's aggregated risk
			st.currentArchive.SummaryRisk = f.Risk
			st.currentArchive.SummaryFindings = f.Findings
			clearProgressLine()
			processCompletedArchive(ctx, st)
			st.currentArchive = nil
			st.currentArchivePath = ""
		} else {
			// This shouldn't happen - summary without members indicates a bug
			log.Printf("[warn] received archive summary for %q but no members were accumulated", f.Path)
		}
		return

	case ap == "":
		// Standalone file (not in an archive)
		if st.currentArchive != nil {
			clearProgressLine()
			processCompletedArchive(ctx, st)
			st.currentArchive = nil
			st.currentArchivePath = ""
		}

		// Strip fragment delimiter (e.g., "file.sh##base64@0" -> "file.sh")
		rp := f.Path
		if idx := strings.Index(f.Path, "##"); idx != -1 {
			rp = f.Path[:idx]
		}
		if rp == st.currentRealPath && st.currentRealFile != nil {
			// Same real file: add as fragment
			st.currentRealFile.Fragments = append(st.currentRealFile.Fragments, f)
			return
		}

		// Different real file: process previous and start new
		if st.currentRealFile != nil {
			clearProgressLine()
			processRealFile(ctx, st)
			st.currentRealFile = nil
			st.currentRealPath = ""
		}

		// Start new real file
		rf := &RealFileAnalysis{
			RealPath:  rp,
			Fragments: []FileAnalysis{},
		}
		if strings.Contains(f.Path, "##") {
			// This entry itself is a fragment; root file entry may come later
			rf.Fragments = []FileAnalysis{f}
		} else {
			// This is the root file entry
			rf.Root = f
		}
		st.currentRealFile = rf
		st.currentRealPath = rp

		// Log file processing start
		if st.logger != nil {
			st.logger.Info("file_started",
				"file_path", rp,
				"file_name", filepath.Base(rp),
			)
		}

	case ap != st.currentArchivePath:
		// Different archive: process everything pending
		if st.currentArchive != nil {
			clearProgressLine()
			processCompletedArchive(ctx, st)
		}
		if st.currentRealFile != nil {
			clearProgressLine()
			processRealFile(ctx, st)
			st.currentRealFile = nil
			st.currentRealPath = ""
		}
		st.currentArchive = &ArchiveAnalysis{
			ArchivePath: ap,
			Members:     []FileAnalysis{f},
		}
		st.currentArchivePath = ap
		st.archiveStartTime = time.Now()

		// Log archive processing start
		if st.logger != nil {
			st.logger.Info("archive_started",
				"archive_path", ap,
				"archive_name", filepath.Base(ap),
			)
		}

	default:
		// Same archive: just add to current archive members
		st.currentArchive.Members = append(st.currentArchive.Members, f)

		// Log archive member processing
		if st.logger != nil {
			st.logger.Debug("archive_member",
				"archive_path", ap,
				"member_path", f.Path,
				"member_name", filepath.Base(f.Path),
				"member_count", len(st.currentArchive.Members),
			)
		}
	}
}

func processCompletedArchive(ctx context.Context, st *streamState) {
	archive := st.currentArchive
	if archive == nil || len(archive.Members) == 0 {
		return
	}

	st.stats.totalFiles += len(archive.Members)

	archiveName := filepath.Base(archive.ArchivePath)
	processingDuration := time.Since(st.archiveStartTime)

	// Helper to log completion with common fields
	logCompletion := func(outcome string, extraFields ...any) {
		if st.logger != nil {
			fields := []any{
				"archive_path", archive.ArchivePath,
				"archive_name", archiveName,
				"member_count", len(archive.Members),
				"duration_ms", processingDuration.Milliseconds(),
				"outcome", outcome,
			}
			fields = append(fields, extraFields...)
			st.logger.Info("archive_completed", fields...)
		}
	}

	needsRev, isValidation := archiveNeedsReview(archive, st.cfg.knownGood, st.cfg.validateEvery)
	if !needsRev {
		mode := "bad"
		reason := "already has detections"
		if st.cfg.knownGood {
			mode = "good"
			reason = "archive has insufficient concerning findings (≤1 suspicious, 0 hostile)"
		}

		// Save training data for properly classified archives
		if st.cfg.trainingDataDir != "" {
			// Concatenate all member JSONL lines (full cleave output)
			var allLines []string
			for _, m := range archive.Members {
				if m.RawJSONL != "" {
					allLines = append(allLines, m.RawJSONL)
				}
			}
			if len(allLines) > 0 {
				combinedJSONL := strings.Join(allLines, "\n")
				if err := saveTrainingData(st.cfg.trainingDataDir, archive.ArchivePath, combinedJSONL); err != nil {
					fmt.Fprintf(os.Stderr, "   %s✗%s Training save failed: %s: %v\n", colorRed, colorReset, filepath.Base(archive.ArchivePath), err)
				} else {
					fmt.Fprintf(os.Stderr, "   %s💾%s %s (%d members)\n", colorDim, colorReset, filepath.Base(archive.ArchivePath), len(allLines))
				}
			} else {
				fmt.Fprintf(os.Stderr, "   %s⚠%s No JSONL data for training: %s\n", colorYellow, colorReset, filepath.Base(archive.ArchivePath))
			}
		}

		st.stats.skippedNoReview++
		logCompletion("skipped_no_review", "reason", reason, "mode", mode)
		return
	}

	archiveHash := hashString(archive.ArchivePath)
	if wasAnalyzed(ctx, st.cfg.db, archiveHash, st.dbMode) {
		st.stats.skippedCached++
		logCompletion("skipped_cached", "cache_hash", archiveHash)
		return
	}

	// Calculate aggregate findings across all members for display
	aggHostile, aggSuspicious := 0, 0
	type fileFindings struct {
		path     string
		findings []Finding
	}
	var filesWithFindings []fileFindings

	for _, m := range archive.Members {
		var concerningFindings []Finding
		for _, f := range m.Findings {
			switch strings.ToLower(f.Crit) {
			case "hostile":
				aggHostile++
				concerningFindings = append(concerningFindings, f)
			case "suspicious":
				aggSuspicious++
				concerningFindings = append(concerningFindings, f)
			default:
				// ignore other criticality levels
			}
		}
		// Track files with any hostile/suspicious findings
		if len(concerningFindings) > 0 {
			filesWithFindings = append(filesWithFindings, fileFindings{
				path:     m.Path,
				findings: concerningFindings,
			})
		}
	}

	if isValidation {
		fmt.Fprintf(os.Stderr, "\n🔍 %s[VALIDATION]%s %s\n", colorCyan, colorReset, archiveName)
	} else {
		fmt.Fprintf(os.Stderr, "\n📦 %s\n", archiveName)
	}
	fmt.Fprintf(os.Stderr, "   Files: %d total, %d with concerning findings\n", len(archive.Members), len(filesWithFindings))

	// Show aggregate findings that triggered the review
	var aggParts []string
	if aggHostile > 0 {
		aggParts = append(aggParts, fmt.Sprintf("%d hostile", aggHostile))
	}
	if aggSuspicious > 0 {
		aggParts = append(aggParts, fmt.Sprintf("%d suspicious", aggSuspicious))
	}
	if len(aggParts) > 0 {
		fmt.Fprintf(os.Stderr, "   Archive aggregate: %s across %d files\n",
			strings.Join(aggParts, ", "), len(filesWithFindings))
	}

	// List files with hostile/suspicious findings (up to 10)
	if len(filesWithFindings) > 0 {
		fmt.Fprint(os.Stderr, "   Files with concerning findings:\n")
		for i, ff := range filesWithFindings {
			if i >= 10 {
				fmt.Fprintf(os.Stderr, "   ... and %d more files\n", len(filesWithFindings)-10)
				break
			}
			// Count by criticality for summary
			hostileCount, suspiciousCount := 0, 0
			for _, f := range ff.findings {
				if strings.EqualFold(f.Crit, "hostile") {
					hostileCount++
				} else {
					suspiciousCount++
				}
			}
			var summary []string
			if hostileCount > 0 {
				summary = append(summary, fmt.Sprintf("%d hostile", hostileCount))
			}
			if suspiciousCount > 0 {
				summary = append(summary, fmt.Sprintf("%d suspicious", suspiciousCount))
			}
			fmt.Fprintf(os.Stderr, "   - %s: %s\n", filepath.Base(ff.path), strings.Join(summary, ", "))

			// List individual findings (up to 5 per file)
			for j, f := range ff.findings {
				if j >= 5 {
					fmt.Fprintf(os.Stderr, "       ... and %d more findings\n", len(ff.findings)-5)
					break
				}
				fmt.Fprintf(os.Stderr, "       • %s: %s\n", f.ID, f.Desc)
			}
		}
	}

	reason := "has suspicious/hostile findings"
	if st.cfg.knownBad {
		reason = "missing detections on known-bad sample"
	}
	if isValidation {
		reason = "🔍 validation sample (random audit)"
	}
	activeCount := st.coordinator.activeCount()
	fmt.Fprintf(os.Stderr, "   %s[queue]%s %s%s%s: %s %s(%d active)%s\n",
		colorBlue, colorReset,
		colorBold, filepath.Base(archive.ArchivePath), colorReset,
		reason,
		colorDim, activeCount, colorReset)

	// Save training data for files going to review
	// Validation samples go to normal dir, actual reviews go to review dir
	saveDir := st.cfg.trainingReviewDir
	if isValidation {
		saveDir = st.cfg.trainingDataDir // validation samples are confirmed
	}
	if saveDir != "" {
		var allLines []string
		for _, m := range archive.Members {
			if m.RawJSONL != "" {
				allLines = append(allLines, m.RawJSONL)
			}
		}
		if len(allLines) > 0 {
			combinedJSONL := strings.Join(allLines, "\n")
			if err := saveTrainingData(saveDir, archive.ArchivePath, combinedJSONL); err != nil {
				fmt.Fprintf(os.Stderr, "   %s✗%s Training save failed: %s: %v\n", colorRed, colorReset, filepath.Base(archive.ArchivePath), err)
			} else {
				fmt.Fprintf(os.Stderr, "   %s💾%s %s (%d members, review)\n", colorDim, colorReset, filepath.Base(archive.ArchivePath), len(allLines))
			}
		} else {
			fmt.Fprintf(os.Stderr, "   %s⚠%s No JSONL data for training: %s\n", colorYellow, colorReset, filepath.Base(archive.ArchivePath))
		}
	}

	// Submit to coordinator for concurrent review (non-blocking unless buffer full)
	// Make a copy of the archive since st.currentArchive will be reused
	archiveCopy := &ArchiveAnalysis{
		ArchivePath:     archive.ArchivePath,
		Members:         append([]FileAnalysis(nil), archive.Members...),
		SummaryRisk:     archive.SummaryRisk,
		SummaryFindings: append([]Finding(nil), archive.SummaryFindings...),
	}
	st.coordinator.submit(reviewJob{archive: archiveCopy, isValidation: isValidation})
	logCompletion("queued_for_review", "files_with_concerns", len(filesWithFindings), "is_validation", isValidation)
}

func processRealFile(ctx context.Context, st *streamState) {
	rf := st.currentRealFile
	if rf == nil || rf.RealPath == "" {
		return
	}

	st.stats.totalFiles++
	st.stats.totalStandaloneFiles++

	needsRev, isValidation := realFileNeedsReview(rf, st.cfg.knownGood, st.cfg.validateEvery)
	if !needsRev {
		// Save training data for properly classified files
		if st.cfg.trainingDataDir != "" {
			// Collect all JSONL lines (root + fragments)
			var allLines []string
			if rf.Root.RawJSONL != "" {
				allLines = append(allLines, rf.Root.RawJSONL)
			}
			for _, frag := range rf.Fragments {
				if frag.RawJSONL != "" {
					allLines = append(allLines, frag.RawJSONL)
				}
			}
			if len(allLines) > 0 {
				combinedJSONL := strings.Join(allLines, "\n")
				if err := saveTrainingData(st.cfg.trainingDataDir, rf.RealPath, combinedJSONL); err != nil {
					fmt.Fprintf(os.Stderr, "   %s✗%s Training save failed: %s: %v\n", colorRed, colorReset, filepath.Base(rf.RealPath), err)
				} else {
					fmt.Fprintf(os.Stderr, "   %s💾%s %s\n", colorDim, colorReset, filepath.Base(rf.RealPath))
				}
			} else {
				fmt.Fprintf(os.Stderr, "   %s⚠%s No JSONL data for training: %s\n", colorYellow, colorReset, filepath.Base(rf.RealPath))
			}
		}
		st.stats.skippedNoReview++
		return
	}

	h, err := hashFile(rf.RealPath)
	if err != nil {
		h = hashString(rf.RealPath)
	}
	if wasAnalyzed(ctx, st.cfg.db, h, st.dbMode) {
		st.stats.skippedCached++
		return
	}

	// Aggregate findings from root and all fragments
	agg := rf.Root
	if agg.Path == "" {
		agg.Path = rf.RealPath
	}
	for _, frag := range rf.Fragments {
		agg.Findings = append(agg.Findings, frag.Findings...)
	}

	if isValidation {
		fmt.Fprintf(os.Stderr, "\n🔍 %s[VALIDATION]%s %s\n", colorCyan, colorReset, rf.RealPath)
	} else {
		fmt.Fprintf(os.Stderr, "\n%s▸ %s%s\n", colorDim, rf.RealPath, colorReset)
	}
	if len(rf.Fragments) > 0 {
		fmt.Fprintf(os.Stderr, "   (with %d decoded fragment(s))\n", len(rf.Fragments))
	}

	var maxCrit string
	for _, f := range agg.Findings {
		if critRank[strings.ToLower(f.Crit)] > critRank[strings.ToLower(maxCrit)] {
			maxCrit = f.Crit
		}
	}
	if maxCrit != "" {
		critClr := critColor(maxCrit)
		fmt.Fprintf(os.Stderr, "   Risk: %s%s%s, Findings: %d\n", critClr, maxCrit, colorReset, len(agg.Findings))
	}

	reason := "has suspicious/hostile findings"
	if st.cfg.knownBad {
		reason = "missing detections on known-bad sample"
	}
	if isValidation {
		reason = "🔍 validation sample (random audit)"
	}
	activeCount := st.coordinator.activeCount()
	fmt.Fprintf(os.Stderr, "   %s[queue]%s %s%s%s: %s %s(%d active)%s\n",
		colorBlue, colorReset,
		colorBold, filepath.Base(rf.RealPath), colorReset,
		reason,
		colorDim, activeCount, colorReset)

	// Save training data for files going to review
	// Validation samples go to normal dir, actual reviews go to review dir
	saveDir := st.cfg.trainingReviewDir
	if isValidation {
		saveDir = st.cfg.trainingDataDir // validation samples are confirmed
	}
	if saveDir != "" {
		var allLines []string
		if rf.Root.RawJSONL != "" {
			allLines = append(allLines, rf.Root.RawJSONL)
		}
		for _, frag := range rf.Fragments {
			if frag.RawJSONL != "" {
				allLines = append(allLines, frag.RawJSONL)
			}
		}
		if len(allLines) > 0 {
			combinedJSONL := strings.Join(allLines, "\n")
			if err := saveTrainingData(saveDir, rf.RealPath, combinedJSONL); err != nil {
				fmt.Fprintf(os.Stderr, "   %s✗%s Training save failed: %s: %v\n", colorRed, colorReset, filepath.Base(rf.RealPath), err)
			} else {
				fmt.Fprintf(os.Stderr, "   %s💾%s %s (review)\n", colorDim, colorReset, filepath.Base(rf.RealPath))
			}
		} else {
			fmt.Fprintf(os.Stderr, "   %s⚠%s No JSONL data for training: %s\n", colorYellow, colorReset, filepath.Base(rf.RealPath))
		}
	}

	// Submit to coordinator for concurrent review (non-blocking unless buffer full)
	// Make a copy of the file since st.currentRealFile will be reused
	fileCopy := &RealFileAnalysis{
		RealPath:  rf.RealPath,
		Root:      rf.Root,
		Fragments: append([]FileAnalysis(nil), rf.Fragments...),
	}
	st.coordinator.submit(reviewJob{file: fileCopy, isValidation: isValidation})

	// Log file queued for review
	if st.logger != nil {
		st.logger.Info("file_queued_for_review",
			"file_path", rf.RealPath,
			"file_name", filepath.Base(rf.RealPath),
			"fragment_count", len(rf.Fragments),
			"is_validation", isValidation,
		)
	}
}

// needsReview determines if a file needs AI review based on mode.
// Returns (needsReview, isValidationSample).
// --good: Review files WITH hostile findings OR 2+ suspicious findings (reduce false positives).
//
//	Up to 1 suspicious finding is acceptable for known-good samples.
//
// --bad: Review files WITHOUT suspicious/hostile findings (find false negatives).
//
// When validateEvery > 0, randomly selects 1 in N files that would normally be skipped
// for validation review (checking for sneaky issues even in "passing" files).
func needsReview(f FileAnalysis, knownGood bool, validateEvery int) (review bool, isValidation bool) {
	if !knownGood {
		// Known-bad mode: review if no suspicious/hostile findings (FN check)
		for _, finding := range f.Findings {
			c := strings.ToLower(finding.Crit)
			if c == "suspicious" || c == "hostile" {
				// Has detection - normally skip, but maybe validate
				if validateEvery > 0 && rand.IntN(validateEvery) == 0 { //nolint:gosec // non-cryptographic sampling
					return true, true // Validation sample
				}
				return false, false // Has detection, skip review
			}
		}
		return true, false // No detection, needs review
	}

	// Known-good mode: count hostile and suspicious separately
	hostileCount := 0
	suspiciousCount := 0
	for _, finding := range f.Findings {
		switch strings.ToLower(finding.Crit) {
		case "hostile":
			hostileCount++
		case "suspicious":
			suspiciousCount++
		default:
			// ignore other criticality levels
		}
	}

	// Review if: any hostile OR 2+ suspicious
	if hostileCount > 0 || suspiciousCount > 1 {
		return true, false // Normal review needed
	}

	// Would normally skip - but maybe validate
	if validateEvery > 0 && rand.IntN(validateEvery) == 0 { //nolint:gosec // non-cryptographic sampling
		return true, true // Validation sample
	}
	return false, false
}

// realFileNeedsReview determines if a real file (with all its fragments) needs review.
// Returns (needsReview, isValidationSample).
func realFileNeedsReview(rf *RealFileAnalysis, knownGood bool, validateEvery int) (review bool, isValidation bool) {
	// Aggregate findings from root and all fragments for accurate counting
	agg := FileAnalysis{
		Path:     rf.RealPath,
		Findings: append([]Finding{}, rf.Root.Findings...),
	}
	for _, frag := range rf.Fragments {
		agg.Findings = append(agg.Findings, frag.Findings...)
	}
	return needsReview(agg, knownGood, validateEvery)
}

// sanityCheck runs cleave on /bin/ls to catch code errors early.
func sanityCheck(ctx context.Context, cfg *config) error {
	const testFile = "/bin/ls"
	fmt.Fprintf(os.Stderr, "Sanity check: running cleave on %s...\n", testFile)

	cmd := exec.CommandContext(ctx, cfg.cleaveBin, "--format", "jsonl", "--validate=true", testFile) //nolint:gosec // cleaveBin is built from trusted cargo
	if cfg.useCargo {
		cmd.Dir = cfg.repoRoot // Run from repo root if using cargo
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprint(os.Stderr, "\n=== SANITY CHECK FAILED ===\n")
		errText := strings.TrimSpace(stderr.String())
		if stderr.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stderr:\n%s\n", stderr.String())
		}
		if stdout.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stdout:\n%s\n", stdout.String())
		}
		if errText == "" {
			errText = strings.TrimSpace(stdout.String())
		}
		if errText != "" {
			return fmt.Errorf("cleave failed on %s: %w: %s", testFile, err, errText)
		}
		return fmt.Errorf("cleave failed on %s: %w", testFile, err)
	}

	fmt.Fprint(os.Stderr, "Sanity check passed.\n\n")
	return nil
}

func isYAMLTraitIssue(msg string) bool {
	s := strings.ToLower(msg)
	if strings.Contains(s, "trait configuration warning") {
		return true
	}
	if strings.Contains(s, "fix these issues in the yaml files") {
		return true
	}
	hasYAML := strings.Contains(s, ".yaml") || strings.Contains(s, ".yml") || strings.Contains(s, "yaml")
	hasTraitContext := strings.Contains(s, "trait") || strings.Contains(s, "traits/")
	return hasYAML && hasTraitContext
}

func buildYAMLTraitFixPrompt(cfg *config, phase, failureOutput string) string {
	return fmt.Sprintf(`Fix cleave trait YAML issues only.

Failure phase: %s

Error output:
%s

Hard requirements:
- Only edit existing YAML trait files under %s/traits/ (*.yaml or *.yml).
- Do NOT edit any Rust code, Go code, scripts, docs, tests, or non-YAML files.
- Focus only on YAML trait parser/configuration issues from the error output.
- Keep trait IDs, taxonomy, and intent intact unless needed to fix the YAML issue.
- Make minimal edits.

After editing, validate with:
%s --format jsonl --validate=true /bin/ls

If validation still fails with YAML trait issues, continue fixing YAML until it passes.
When done, stop.`,
		phase,
		failureOutput,
		cfg.repoRoot,
		cfg.cleaveBin,
	)
}

func invokeYAMLTraitFixer(ctx context.Context, cfg *config, phase, failureOutput string, attempt, maxAttempts int) error {
	fmt.Fprintf(os.Stderr, "%s⚠️  YAML trait issue detected during %s%s %s(attempt %d/%d)%s\n",
		colorYellow, phase, colorReset, colorDim, attempt, maxAttempts, colorReset)
	fmt.Fprintf(os.Stderr, "   %s[repair]%s Submitting YAML-only fix task to %s%s%s\n",
		colorMagenta, colorReset, colorCyan, strings.Join(cfg.providers, " → "), colorReset)

	prompt := buildYAMLTraitFixPrompt(cfg, phase, failureOutput)
	sid := generateSessionID()

	// Try each provider in order until one succeeds
	var lastErr error
	for i, p := range cfg.providers {
		cfg.provider = p
		if i > 0 {
			fmt.Fprintf(os.Stderr, "%s>>>%s Trying next provider: %s%s%s\n",
				colorCyan, colorReset, colorCyan, p, colorReset)
		}

		// Validate provider is responsive before running main task
		if err := validateProvider(ctx, cfg); err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "%s<<<%s %s%s%s validation failed: %v\n",
				colorRed, colorReset, colorRed, p, colorReset, err)
			continue
		}

		tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
		repairPrefix := fmt.Sprintf("%s[repair]%s ", colorMagenta, colorReset)
		err := runAIWithStreaming(tctx, cfg, prompt, sid, repairPrefix)
		cancel()

		if err == nil {
			return nil
		}

		lastErr = err
		fmt.Fprintf(os.Stderr, "%s[repair]%s <<< %s%s%s failed: %v\n",
			colorMagenta, colorReset, colorRed, p, colorReset, err)

		// Check if context was cancelled (user interrupt)
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted: %w", ctx.Err())
		}
	}

	return fmt.Errorf("all providers failed, last error: %w", lastErr)
}

// countFindingsByCrit counts hostile and suspicious findings.
func countFindingsByCrit(findings []Finding) (hostileCount, suspiciousCount int) {
	for _, fd := range findings {
		switch strings.ToLower(fd.Crit) {
		case "hostile":
			hostileCount++
		case "suspicious":
			suspiciousCount++
		default:
			// ignore other criticality levels
		}
	}
	return hostileCount, suspiciousCount
}

// setupReportPaths configures report and gap analysis paths in promptData based on mode.
func setupReportPaths(data *promptData, cfg *config, fileHash string, hostileCount, suspiciousCount int) error {
	if cfg.knownBad {
		data.MayBeBenign = true
		reportsDir, err := dataDir("reports")
		if err != nil {
			return fmt.Errorf("failed to create reports directory: %w", err)
		}
		data.ReportPath = filepath.Join(reportsDir, fileHash+".md")

		gapsDir, err := dataDir("gaps")
		if err != nil {
			return fmt.Errorf("failed to create gaps directory: %w", err)
		}
		data.GapAnalysisPath = filepath.Join(gapsDir, fileHash+".md")

		if _, err := os.Stat(data.ReportPath); err == nil {
			data.ReportExists = true
		}
	} else {
		data.MayBeBad = true
		data.HasHostileFindings = hostileCount > 0
		data.HasSuspiciousFindings = suspiciousCount > 0

		if reportsDir, err := dataDir("reports"); err == nil {
			badReportPath := filepath.Join(reportsDir, fileHash+".md")
			if _, err := os.Stat(badReportPath); err == nil {
				data.HasRelatedBadReport = true
				data.RelatedBadReportPath = badReportPath
			}
		}
	}
	return nil
}

// buildFindingsSummary builds a markdown summary of hostile/suspicious findings.
func buildFindingsSummary(findings []Finding) string {
	var susp, host []Finding
	for _, fd := range findings {
		switch strings.ToLower(fd.Crit) {
		case "hostile":
			host = append(host, fd)
		case "suspicious":
			susp = append(susp, fd)
		default:
			// ignore other criticality levels
		}
	}
	if len(host) == 0 && len(susp) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\n\n## Current Findings\n")
	if len(host) > 0 {
		sb.WriteString("**Hostile:**\n")
		for _, fd := range host {
			fmt.Fprintf(&sb, "- `%s`: %s\n", fd.ID, fd.Desc)
		}
	}
	if len(susp) > 0 {
		sb.WriteString("**Suspicious:**\n")
		for _, fd := range susp {
			fmt.Fprintf(&sb, "- `%s`: %s\n", fd.ID, fd.Desc)
		}
	}
	return sb.String()
}

// collectArchiveFindings gathers all findings from archive members.
func collectArchiveFindings(members []FileAnalysis) []Finding {
	var all []Finding
	for _, m := range members {
		all = append(all, m.Findings...)
	}
	return all
}

// buildFileEntry creates a fileEntry from a FileAnalysis with summary stats.
func buildFileEntry(m FileAnalysis) fileEntry {
	counts := make(map[string]int)
	maxCrit := 0
	for _, f := range m.Findings {
		c := strings.ToLower(f.Crit)
		counts[c]++
		if r := critRank[c]; r > maxCrit {
			maxCrit = r
		}
	}
	var parts []string
	total := 0
	for _, level := range []string{"hostile", "suspicious", "notable"} {
		if n := counts[level]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, level))
			total += n
		}
	}
	path := m.ExtractedPath
	if path == "" {
		path = m.Path
	}
	return fileEntry{
		Path:    path,
		Summary: strings.Join(parts, ", "),
		MaxCrit: maxCrit,
		Total:   total,
	}
}

// buildArchiveFileEntries builds sorted file entries for an archive.
func buildArchiveFileEntries(sourceFiles []FileAnalysis, extractDirRoot string) (entries []fileEntry, extractDir string) {
	for _, m := range sourceFiles {
		if m.ExtractedPath != "" && extractDir == "" {
			rel := strings.TrimPrefix(m.ExtractedPath, extractDirRoot+"/")
			if idx := strings.Index(rel, "/"); idx > 0 {
				extractDir = filepath.Join(extractDirRoot, rel[:idx])
			} else {
				extractDir = m.ExtractedPath
			}
		}
		entries = append(entries, buildFileEntry(m))
	}

	// Sort by severity (hostile > suspicious > notable), then by count.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].MaxCrit != entries[j].MaxCrit {
			return entries[i].MaxCrit > entries[j].MaxCrit
		}
		return entries[i].Total > entries[j].Total
	})

	// Take top 10.
	if len(entries) > 10 {
		entries = entries[:10]
	}
	return entries, extractDir
}

// countFilesWithConcerns counts archive members with hostile/suspicious findings.
func countFilesWithConcerns(members []FileAnalysis) int {
	count := 0
	for _, m := range members {
		for _, f := range m.Findings {
			c := strings.ToLower(f.Crit)
			if c == "hostile" || c == "suspicious" {
				count++
				break
			}
		}
	}
	return count
}

// tryProviders attempts to run the AI task with each provider in order until one succeeds.
func tryProviders(ctx context.Context, cfg *config, prompt, sid, prefix string, workerID int, rc *reviewCoordinator) error {
	var lastErr error
	for i, p := range cfg.providers {
		cfg.provider = p

		rc.mu.Lock()
		rc.workers[workerID].provider = p
		rc.mu.Unlock()

		if i > 0 {
			fmt.Fprintf(os.Stderr, "%s>>> Trying next provider: %s\n", prefix, p)
		}

		if err := validateProvider(ctx, cfg); err != nil {
			lastErr = err
			fmt.Fprintf(os.Stderr, "%s<<< %s validation failed: %v\n", prefix, p, err)
			continue
		}

		tctx, cancel := context.WithTimeout(ctx, cfg.timeout)
		err := runAIWithStreaming(tctx, cfg, prompt, sid, prefix)
		cancel()

		if err == nil {
			return nil
		}

		lastErr = err
		fmt.Fprintf(os.Stderr, "%s<<< %s failed: %v\n", prefix, p, err)

		if ctx.Err() != nil {
			return fmt.Errorf("interrupted: %w", ctx.Err())
		}
	}
	return fmt.Errorf("all providers failed, last error: %w", lastErr)
}

func invokeAI(ctx context.Context, cfg *config, f FileAnalysis, isValidation bool, sid string, workerID int, rc *reviewCoordinator) error {
	// Check for misclassification marker - skip if present.
	if hasMarker, markerType := hasMisclassificationMarker(f.Path); hasMarker {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "  [skip] %s: marked as %s (._<filename>.%s exists)\n",
				filepath.Base(f.Path), markerType, markerType)
		}
		return nil
	}

	// Compute file hash for report paths.
	fileHash, err := hashFile(f.Path)
	if err != nil {
		fileHash = hashString(f.Path) // Fallback to path hash
	}

	hostileCount, suspiciousCount := countFindingsByCrit(f.Findings)

	data := promptData{
		Path:               f.Path,
		CleaveBin:          cfg.cleaveBin,
		TraitsDir:          cfg.repoRoot + "/traits/",
		IsArchive:          false,
		IsBad:              cfg.knownBad,
		IsValidationSample: isValidation,
		BenignMarkerPath:   misclassificationMarkerPath(f.Path, "BENIGN"),
		BadMarkerPath:      misclassificationMarkerPath(f.Path, "BAD"),
	}

	if err := setupReportPaths(&data, cfg, fileHash, hostileCount, suspiciousCount); err != nil {
		return err
	}

	prompt, err := buildPrompt(&data)
	if err != nil {
		return fmt.Errorf("build prompt for %s: %w", f.Path, err)
	}

	// Add findings summary for good files.
	if cfg.knownGood && (hostileCount > 0 || suspiciousCount > 0) {
		prompt += buildFindingsSummary(f.Findings)
	}

	if f.ExtractedPath != "" {
		prompt += fmt.Sprintf("\n\n## Extracted Sample\nThe file has been extracted to: %s\n"+
			"Use this path for binary analysis tools (radare2, strings, objdump, xxd, nm).", f.ExtractedPath)
	}

	return tryProviders(ctx, cfg, prompt, sid, rc.workerPrefix(workerID), workerID, rc)
}

func invokeAIArchive(ctx context.Context, cfg *config, a *ArchiveAnalysis, isValidation bool, sid string, workerID int, rc *reviewCoordinator) error {
	// Check for misclassification marker - skip if present.
	if hasMarker, markerType := hasMisclassificationMarker(a.ArchivePath); hasMarker {
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "  [skip] %s: marked as %s (._<filename>.%s exists)\n",
				filepath.Base(a.ArchivePath), markerType, markerType)
		}
		return nil
	}

	// Select source files based on mode.
	sourceFiles := a.Members
	if cfg.knownGood {
		sourceFiles = archiveProblematicMembers(a, cfg.knownGood)
	}

	fileEntries, extractDir := buildArchiveFileEntries(sourceFiles, cfg.extractDir)

	cleavePath := extractDir
	if cleavePath == "" {
		cleavePath = a.ArchivePath
	}

	fileHash, err := hashFile(a.ArchivePath)
	if err != nil {
		fileHash = hashString(a.ArchivePath)
	}

	allFindings := collectArchiveFindings(a.Members)
	hostileCount, suspiciousCount := countFindingsByCrit(allFindings)

	data := promptData{
		Path:               cleavePath,
		ArchiveName:        filepath.Base(a.ArchivePath),
		Files:              fileEntries,
		Count:              countFilesWithConcerns(a.Members),
		CleaveBin:          cfg.cleaveBin,
		TraitsDir:          cfg.repoRoot + "/traits/",
		IsArchive:          true,
		IsBad:              cfg.knownBad,
		IsValidationSample: isValidation,
		BenignMarkerPath:   misclassificationMarkerPath(a.ArchivePath, "BENIGN"),
		BadMarkerPath:      misclassificationMarkerPath(a.ArchivePath, "BAD"),
	}

	if err := setupReportPaths(&data, cfg, fileHash, hostileCount, suspiciousCount); err != nil {
		return err
	}

	prompt, err := buildPrompt(&data)
	if err != nil {
		return fmt.Errorf("build prompt for %s: %w", a.ArchivePath, err)
	}

	// Add findings summary for good archives.
	if cfg.knownGood && (hostileCount > 0 || suspiciousCount > 0) {
		prompt += buildFindingsSummary(allFindings)
	}

	return tryProviders(ctx, cfg, prompt, sid, rc.workerPrefix(workerID), workerID, rc)
}

// validateProvider tests if the AI provider is responsive with a simple test prompt.
// Returns an error if the provider doesn't respond within 1 minute.
// Only validates each provider once per program execution.
func validateProvider(ctx context.Context, cfg *config) error {
	// Fast path: check without lock
	validatedProvidersMu.Lock()
	if validatedProviders[cfg.provider] {
		validatedProvidersMu.Unlock()
		return nil
	}
	validatedProvidersMu.Unlock()

	fmt.Fprintf(os.Stderr, "%s>>>%s Validating provider %s%s%s (60s timeout)...\n",
		colorCyan, colorReset, colorCyan, cfg.provider, colorReset)

	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	testCfg := *cfg
	testCfg.timeout = 60 * time.Second

	if err := runAIWithStreaming(testCtx, &testCfg, "Say OK", generateSessionID(), ""); err != nil {
		return fmt.Errorf("provider validation failed: %w", err)
	}

	validatedProvidersMu.Lock()
	validatedProviders[cfg.provider] = true
	validatedProvidersMu.Unlock()

	return nil
}

func runAIWithStreaming(ctx context.Context, cfg *config, prompt, sid, prefix string) error {
	var cmd *exec.Cmd

	// Handle provider:model syntax (e.g., "gemini:gemini-2.5-pro")
	provider := cfg.provider
	modelOverride := ""
	if idx := strings.Index(provider, ":"); idx != -1 {
		modelOverride = provider[idx+1:]
		provider = provider[:idx]
	}

	// Build command args (prompt sent via stdin)
	switch provider {
	case "claude":
		args := []string{
			"--verbose",
			"--output-format", "stream-json",
			"--dangerously-skip-permissions",
			"--session-id", sid,
		}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "claude", args...)
	case "gemini":
		args := []string{
			"--yolo",
			"--output-format", "stream-json",
			"--include-directories", cfg.repoRoot,
			"--include-directories", cfg.extractDir,
		}
		if home, err := os.UserHomeDir(); err == nil {
			args = append(args, "--include-directories", filepath.Join(home, "data"))
		}
		// Use model from provider:model syntax, or explicit --model flag
		if modelOverride != "" {
			args = append(args, "--model", modelOverride)
		} else if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "gemini", args...)
	case "codex":
		args := []string{"exec", "--json", "--full-auto", "--sandbox", "danger-full-access"}
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		args = append(args, "-")
		cmd = exec.CommandContext(ctx, "codex", args...)
	case "opencode":
		var args []string
		if cfg.model != "" {
			args = append(args, "--model", cfg.model)
		}
		cmd = exec.CommandContext(ctx, "opencode", args...)
	default:
		return fmt.Errorf("unknown provider: %s", cfg.provider)
	}

	cmd.Dir = cfg.repoRoot

	// Always print the full prompt for visibility
	fmt.Fprintf(os.Stderr, "%s>>> %s %s\n", prefix, cmd.Path, strings.Join(cmd.Args[1:], " "))
	fmt.Fprintf(os.Stderr, "%s>>> Prompt (%d bytes):\n", prefix, len(prompt))
	for _, line := range strings.Split(prompt, "\n") {
		fmt.Fprintf(os.Stderr, "%s%s%s%s\n", prefix, colorBrightWhite, line, colorReset)
	}
	fmt.Fprintf(os.Stderr, "%s>>> End Prompt\n", prefix)

	// Set up pipes
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", cfg.provider, err)
	}
	if cfg.verbose {
		fmt.Fprintf(os.Stderr, "%s>>> PID %d\n", prefix, cmd.Process.Pid)
	}

	// Write prompt to stdin, then close to signal EOF
	go func() {
		defer stdinPipe.Close()           //nolint:errcheck // close error irrelevant after write
		io.WriteString(stdinPipe, prompt) //nolint:errcheck,gosec // write error handled by process exit
	}()

	var (
		output     []string
		outputMu   sync.Mutex
		lastActive = time.Now()
		activeMu   sync.Mutex
	)
	done := make(chan struct{}, 1) // buffered to prevent goroutine leak on early return

	// Read stderr with prefix (for messages like "YOLO mode is enabled")
	go func() {
		sc := bufio.NewScanner(stderrPipe)
		for sc.Scan() {
			line := sc.Text()
			if line != "" {
				fmt.Fprintf(os.Stderr, "%s%s\n", prefix, line)
			}
		}
	}()

	// Read stdout
	go func() {
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 1024*1024), 10*1024*1024)
		for sc.Scan() {
			ln := sc.Text()
			displayStreamEvent(ln, prefix)
			outputMu.Lock()
			output = append(output, ln)
			outputMu.Unlock()
			activeMu.Lock()
			lastActive = time.Now()
			activeMu.Unlock()
		}
		done <- struct{}{}
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			goto waitForExit
		case <-ticker.C:
			if cmd.ProcessState == nil {
				activeMu.Lock()
				idle := time.Since(lastActive)
				activeMu.Unlock()

				if idle > cfg.idleTimeout {
					fmt.Fprintf(os.Stderr, "\n%s>>> Idle timeout (%v), killing...\n", prefix, cfg.idleTimeout)
					cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill on timeout
					return fmt.Errorf("idle timeout: no output for %v", cfg.idleTimeout)
				}
			}
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "\n%s>>> Timeout, killing...\n", prefix)
			cmd.Process.Kill() //nolint:errcheck,gosec // best-effort kill on context cancel
			return fmt.Errorf("timeout: %w", ctx.Err())
		}
	}
waitForExit:

	err = cmd.Wait()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errors.New("exceeded time limit")
		}
		outputMu.Lock()
		all := strings.Join(output, "\n")
		outputMu.Unlock()
		return fmt.Errorf("%s failed (exit %d): %s", cfg.provider, cmd.ProcessState.ExitCode(), all)
	}
	return nil
}

// displayStreamEvent parses a stream-json line and displays relevant info.
// Handles both Claude format (type: assistant/result) and Gemini format (type: message).
func displayStreamEvent(line, prefix string) {
	var ev map[string]any
	if json.Unmarshal([]byte(line), &ev) != nil {
		return
	}

	switch ev["type"] {
	case "thread.started":
		if id, ok := ev["thread_id"].(string); ok && id != "" {
			fmt.Fprintf(os.Stderr, "%s%s[codex]%s thread %s\n", prefix, colorGreen, colorReset, id)
		}
	case "turn.started":
		fmt.Fprintf(os.Stderr, "%s%s[codex]%s turn started\n", prefix, colorGreen, colorReset)
	case "turn.completed":
		displayTurnCompleted(ev, prefix)
	case "turn.failed":
		fmt.Fprintf(os.Stderr, "%s%s[codex]%s %sturn failed%s\n", prefix, colorRed, colorReset, colorRed, colorReset)
	case "item/agentMessage/delta", "item/plan/delta":
		displayDelta(ev, "delta", "text")
	case "item/commandExecution/outputDelta", "item/fileChange/outputDelta":
		displayDelta(ev, "delta", "output")
	case "item.started", "item.completed":
		displayCodexItem(ev, prefix)
	case "error":
		if msg, ok := ev["message"].(string); ok && msg != "" {
			fmt.Fprintf(os.Stderr, "%s%s[codex] error:%s %s\n", prefix, colorRed, colorReset, msg)
		}
	case "assistant":
		displayClaudeAssistant(ev, prefix)
	case "message":
		// Gemini format: {"type":"message","role":"assistant","content":"...","delta":true}
		if ev["role"] == "assistant" {
			if content, ok := ev["content"].(string); ok && content != "" {
				fmt.Fprintf(os.Stderr, "%s%s\n", prefix, content)
			}
		}
	case "tool_call", "tool", "tool_use":
		if name, ok := ev["name"].(string); ok {
			fmt.Fprintf(os.Stderr, "%s%s[tool]%s %s\n", prefix, colorYellow, colorReset, name)
		}
	case "tool_result", "init", "user":
		// Silently consume: tool results (output already shown), initialization, user prompts
	case "result":
		displayResult(ev, prefix)
	default:
		if evType, ok := ev["type"].(string); ok && evType != "" {
			fmt.Fprintf(os.Stderr, "%s%s[debug]%s unknown event type: %s\n", prefix, colorDim, colorReset, evType)
		}
	}
}

// displayTurnCompleted handles the turn.completed event showing token usage.
func displayTurnCompleted(ev map[string]any, prefix string) {
	usage, ok := ev["usage"].(map[string]any)
	if !ok {
		return
	}
	in, _ := usage["input_tokens"].(float64)   //nolint:errcheck,revive // type assertion ok, defaults to 0
	out, _ := usage["output_tokens"].(float64) //nolint:errcheck,revive // type assertion ok, defaults to 0
	if in > 0 || out > 0 {
		fmt.Fprintf(os.Stderr, "%s%s[codex]%s tokens: %sin=%.0f out=%.0f%s\n",
			prefix, colorGreen, colorReset, colorDim, in, out, colorReset)
	}
}

// displayDelta prints streaming delta content, checking primary and fallback keys.
func displayDelta(ev map[string]any, primaryKey, fallbackKey string) {
	if delta, ok := ev[primaryKey].(string); ok && delta != "" {
		fmt.Fprint(os.Stderr, delta)
		if primaryKey == "delta" && fallbackKey == "text" {
			codexDeltaOpen = true
		}
	} else if text, ok := ev[fallbackKey].(string); ok && text != "" {
		fmt.Fprint(os.Stderr, text)
		if primaryKey == "delta" && fallbackKey == "text" {
			codexDeltaOpen = true
		}
	}
}

// displayCodexItem handles item.started and item.completed events.
func displayCodexItem(ev map[string]any, prefix string) {
	item, ok := ev["item"].(map[string]any)
	if !ok {
		return
	}
	itemType, _ := item["type"].(string) //nolint:errcheck,revive // type assertion ok, defaults to empty

	switch itemType {
	case "agent_message":
		if text, ok := item["text"].(string); ok && text != "" {
			fmt.Fprintf(os.Stderr, "%s%s\n", prefix, text)
		} else if codexDeltaOpen {
			fmt.Fprintln(os.Stderr)
		}
		codexDeltaOpen = false
	case "command_execution":
		if cmd, ok := item["command"].(string); ok && cmd != "" {
			fmt.Fprintf(os.Stderr, "%s%s[tool]%s command: %s\n", prefix, colorYellow, colorReset, cmd)
		}
	case "file_change":
		if path, ok := item["path"].(string); ok && path != "" {
			fmt.Fprintf(os.Stderr, "%s%s[tool]%s file change: %s\n", prefix, colorYellow, colorReset, path)
		}
	case "web_search":
		if q, ok := item["query"].(string); ok && q != "" {
			fmt.Fprintf(os.Stderr, "%s%s[tool]%s web search: %s\n", prefix, colorYellow, colorReset, q)
		}
	case "plan_update":
		fmt.Fprintf(os.Stderr, "%s%s[tool]%s plan update\n", prefix, colorYellow, colorReset)
	default:
		// ignore other item types
	}
}

// displayClaudeAssistant handles Claude format assistant messages.
func displayClaudeAssistant(ev map[string]any, prefix string) {
	msg, ok := ev["message"].(map[string]any)
	if !ok {
		return
	}
	content, ok := msg["content"].([]any)
	if !ok {
		return
	}
	for _, c := range content {
		b, ok := c.(map[string]any)
		if !ok {
			continue
		}
		switch b["type"] {
		case "tool_use":
			displayToolUse(b, prefix)
		case "text":
			if t, ok := b["text"].(string); ok && t != "" {
				fmt.Fprintf(os.Stderr, "%s%s\n", prefix, t)
			}
		default:
			// ignore other content types
		}
	}
}

// displayToolUse handles tool_use content blocks with detail extraction.
func displayToolUse(b map[string]any, prefix string) {
	name, _ := b["name"].(string) //nolint:errcheck,revive // type assertion ok, defaults to empty
	if name == "" {
		name = "unknown"
	}
	input, ok := b["input"].(map[string]any)
	if !ok {
		fmt.Fprintf(os.Stderr, "%s%s[tool]%s %s\n", prefix, colorYellow, colorReset, name)
		return
	}
	detail := extractToolDetail(input)
	if detail != "" {
		fmt.Fprintf(os.Stderr, "%s%s[tool]%s %s: %s\n", prefix, colorYellow, colorReset, name, detail)
	} else {
		fmt.Fprintf(os.Stderr, "%s%s[tool]%s %s\n", prefix, colorYellow, colorReset, name)
	}
}

// extractToolDetail extracts a display-friendly detail from tool input.
func extractToolDetail(input map[string]any) string {
	for _, k := range []string{"description", "command", "pattern", "file_path"} {
		if v, ok := input[k].(string); ok && v != "" {
			if len(v) > 80 {
				return v[:80] + "..."
			}
			return v
		}
	}
	return ""
}

// displayResult handles the result event showing final output and cost.
func displayResult(ev map[string]any, prefix string) {
	if r, ok := ev["result"].(string); ok && r != "" {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s%s--- Result ---%s\n", prefix, colorGreen, colorReset)
		fmt.Fprintf(os.Stderr, "%s%s\n", prefix, r)
	}
	if cost, ok := ev["total_cost_usd"].(float64); ok {
		fmt.Fprintf(os.Stderr, "%s%sCost: $%.4f%s\n", prefix, colorDim, cost, colorReset)
	}
}

// codexDeltaOpen tracks whether we've printed streaming agent deltas and need a newline.
var codexDeltaOpen bool
