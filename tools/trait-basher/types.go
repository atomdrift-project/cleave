package main

import (
	"database/sql"
	"sync"
	"time"
)

// fileEntry holds a file path with its finding summary for display.
type fileEntry struct {
	Path    string // Extracted path
	Summary string // e.g., "4 hostile, 2 suspicious"
	MaxCrit int    // For sorting (3=hostile, 2=suspicious, 1=notable)
	Total   int    // Total high-severity findings
}

// promptData holds values for prompt templates.
type promptData struct {
	Path                  string
	ArchiveName           string
	CleaveBin             string
	TraitsDir             string
	ReportPath            string
	GapAnalysisPath       string
	RelatedBadReportPath  string
	BenignMarkerPath      string
	BadMarkerPath         string
	Files                 []fileEntry
	Count                 int
	IsArchive             bool
	IsBad                 bool
	ReportExists          bool
	HasRelatedBadReport   bool
	MayBeBenign           bool
	MayBeBad              bool
	HasHostileFindings    bool
	HasSuspiciousFindings bool
	IsValidationSample    bool
	ExternalTools         string // Comma-separated list of available external tools (rizin, ghidra, nm, readelf)
}

// config holds all configuration for a trait-basher session.
type config struct {
	db                *sql.DB
	repoRoot          string
	cleaveBin        string
	provider          string
	model             string
	extractDir        string
	trainingDataDir   string // Directory for confirmed files (empty = disabled)
	trainingReviewDir string // Directory for files needing review (empty = disabled)
	dirs              []string
	providers         []string
	timeout           time.Duration
	idleTimeout       time.Duration
	rescanAfter       int
	concurrency       int
	validateEvery     int
	knownGood         bool
	knownBad          bool
	useCargo          bool
	flush             bool
	verbose           bool
}

// reviewJob represents a file or archive to be reviewed by an LLM.
type reviewJob struct {
	archive      *ArchiveAnalysis  // non-nil for archive reviews
	file         *RealFileAnalysis // non-nil for standalone file reviews
	isValidation bool              // true if this is a validation sample (randomly selected for audit)
}

// reviewResult contains the outcome of a review job.
type reviewResult struct {
	err      error
	job      reviewJob
	provider string
	duration time.Duration
}

// Finding represents a matched trait/capability.
type Finding struct {
	ID   string `json:"id"`
	Crit string `json:"crit"`
	Desc string `json:"desc"`
}

// FileAnalysis represents a single analyzed file.
type FileAnalysis struct {
	Path          string    `json:"path"`
	Risk          string    `json:"risk"`
	ExtractedPath string    `json:"extracted_path,omitempty"`
	Findings      []Finding `json:"findings"`
	RawJSONL      string    `json:"-"` // Original JSONL line for training data (not serialized)
}

// ArchiveAnalysis groups files from the same archive for review as a unit.
type ArchiveAnalysis struct {
	ArchivePath     string
	Members         []FileAnalysis
	SummaryRisk     string    // Aggregated risk from archive summary entry
	SummaryFindings []Finding // Archive-level findings (zip-bomb, etc.)
}

// RealFileAnalysis groups a real file with all its encoded/decoded fragments.
type RealFileAnalysis struct {
	RealPath  string         // The real file path (stripped of ## fragment delimiters)
	Root      FileAnalysis   // The root/real file entry
	Fragments []FileAnalysis // All decoded fragment entries (if any)
}

// jsonlEntry represents a single JSONL line from streaming output.
type jsonlEntry struct {
	Type          string    `json:"type"`
	Path          string    `json:"path"`
	FileType      string    `json:"file_type"`
	Risk          string    `json:"risk"`
	ExtractedPath string    `json:"extracted_path,omitempty"`
	Findings      []Finding `json:"findings"`
}

// streamStats tracks streaming analysis statistics.
type streamStats struct {
	scanStartTime        time.Time
	reviewTimeTotal      time.Duration
	archivesReviewed     int
	standaloneReviewed   int
	skippedCached        int
	skippedNoReview      int
	totalFiles           int
	totalStandaloneFiles int
	estimatedTotal       int
	mu                   sync.Mutex
	shouldRestart        bool
}

// critRank maps criticality levels to numeric ranks for comparison.
// component and baseline are both low-value (0), notable=1, suspicious=2, hostile=3
var critRank = map[string]int{"component": 0, "baseline": 0, "notable": 1, "suspicious": 2, "hostile": 3}

// workerState tracks the current state of a single LLM worker slot.
type workerState struct {
	// time.Time first (24 bytes)
	startTime time.Time // when current job/idle started
	// Strings (16 bytes each on 64-bit)
	path     string // current job path (empty if idle)
	provider string // current provider being used
	// Booleans
	busy         bool // true if processing a job
	isValidation bool // true if this is a validation sample (random audit)
}
