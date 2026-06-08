// Command manifest-gen builds a trait-update versions.toml by validating recent
// cleave-traits commits against a per-release engine.
//
// For each recent engine release tag it builds that exact engine (from
// `git archive <tag>` — read-only git, no checkout/worktree), then validates
// recent traits commits against it. Pointers advance independently per release:
// beta = newest passing commit, stable = newest passing commit older than the
// soak window. Validation only walks back to the commit the prior manifest
// already records for that release (the floor) — everything at/below the floor
// is already known-good, so it is never re-validated.
//
// Artifacts are git-archive + xz (reproducible, committed tree only). The
// manifest is then rendered and optionally cosign-signed.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type commit struct {
	full, short, date string
	t                 time.Time
}

type artifact struct {
	key, file, sha, commit, date string
}

type config struct {
	traits, repo, engineOverride, out string
	artifactPrefix                    string
	nReleases, nCommits               int
	soakDays, validDays               int
	channels                          []string
	noValidate, sign                  bool
	identity                          string
}

func main() {
	var c config
	flag.StringVar(&c.traits, "traits", "../cleave-traits", "path to the cleave-traits git repo")
	flag.StringVar(&c.repo, "repo", ".", "path to the cleave (engine) git repo")
	flag.StringVar(&c.engineOverride, "engine", "", "use this binary for ALL releases instead of building per tag (testing)")
	flag.StringVar(&c.out, "out", "dist", "output directory")
	flag.StringVar(&c.artifactPrefix, "artifact-prefix", "",
		"path prepended to each artifact's `file` in the manifest, relative to the manifest (e.g. \"traits/\")")
	flag.IntVar(&c.nReleases, "releases", 2, "recent engine release tags to key the manifest by")
	flag.IntVar(&c.nCommits, "commits", 20, "recent traits commits to consider (the ceiling; the floor bounds the rest)")
	flag.IntVar(&c.soakDays, "soak-days", 7, "stable lags beta by at least this many days")
	flag.IntVar(&c.validDays, "valid-days", 7, "valid_until = now + this many days")
	chans := flag.String("channels", "stable,beta", "channels to populate, in output order")
	flag.BoolVar(&c.noValidate, "no-validate", false, "skip the gate (structure only; unsafe)")
	flag.BoolVar(&c.sign, "sign", false, "cosign-sign the rendered manifest")
	flag.StringVar(&c.identity, "identity", "", "expected signer identity (required with --sign)")
	flag.Parse()
	c.channels = strings.Split(*chans, ",")

	if c.sign && c.identity == "" {
		fatal("--sign requires --identity")
	}
	if err := os.MkdirAll(c.out, 0o755); err != nil {
		fatal("mkdir %s: %v", c.out, err)
	}
	run(&c)
}

func run(c *config) {
	tags := releaseTags(c.repo, c.nReleases) // manifest keys, newest first
	if len(tags) == 0 {
		fatal("no release tags in %s", c.repo)
	}
	commits := traitsCommits(c.traits, c.nCommits) // newest first
	if len(commits) == 0 {
		fatal("no commits in %s", c.traits)
	}
	floors := parseFloors(filepath.Join(c.out, "versions.toml")) // [channel][release]=key
	memo := loadCache(c.out)
	tarCache := map[string][]byte{}
	cutoff := time.Now().UTC().AddDate(0, 0, -c.soakDays)
	logf("releases=%v  considering up to %d traits commits", tags, len(commits))

	// pointers[channel][release] = selected key (short commit)
	pointers := map[string]map[string]string{}
	for _, ch := range c.channels {
		pointers[strings.TrimSpace(ch)] = map[string]string{}
	}

	for _, rel := range tags {
		enginePath, ok := ensureEngine(c, rel)
		if !ok {
			// Can't validate this release: freeze its pointers at the prior manifest.
			for _, ch := range c.channels {
				ch = strings.TrimSpace(ch)
				pointers[ch][rel] = floors[ch][rel]
			}
			logf("release %s: engine unbuildable — pointers frozen at prior", rel)
			continue
		}
		for _, ch := range c.channels {
			ch = strings.TrimSpace(ch)
			floor := floors[ch][rel]
			cand := commits[:floorIndex(commits, floor)] // strictly newer than the floor
			sel := selectPointer(c, enginePath, rel, ch, cand, cutoff, tarCache, memo)
			switch {
			case sel != "":
				// found a newer passing commit
			case floor != "":
				sel = floor // nothing newer qualified — keep the known-good floor
			case ch == "stable":
				sel = pointers["beta"][rel] // fresh manifest, no soaked commit yet
			}
			pointers[ch][rel] = sel
			logf("  %s/%s -> %s (floor=%q, %d candidates)", rel, ch, orNone(sel), floor, len(cand))
		}
	}
	saveCache(c.out, memo)

	arts := buildArtifacts(c, pointers, tarCache)
	validUntil := time.Now().UTC().AddDate(0, 0, c.validDays).Format("2006-01-02T15:04:05Z")
	manifest := render(validUntil, c.artifactPrefix, arts, tags, c.channels, pointers)
	path := filepath.Join(c.out, "versions.toml")
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		fatal("write %s: %v", path, err)
	}
	logf("rendered %s", path)

	if c.sign {
		logf("signing %s as %s (publishes identity to public logs)", path, c.identity)
		exe("", "cosign", "sign-blob", "--new-bundle-format", "--yes",
			"--bundle", path+".sigstore.json", path)
		logf("signed -> %s.sigstore.json (pin: %s)", path, c.identity)
	}
	logf("done.")
}

// selectPointer returns the newest candidate commit that the engine validates
// (and, for stable, that is at least soak-old). "" if none qualify.
func selectPointer(c *config, engine, rel, ch string, cand []commit, cutoff time.Time,
	tarCache map[string][]byte, memo map[string]bool) string {
	for i := range cand {
		cm := cand[i]
		if ch == "stable" && cm.t.After(cutoff) {
			continue // too fresh to be stable
		}
		ok := c.noValidate || validate(c.traits, engine, rel, cm, tarCache, memo)
		if ok {
			return cm.short
		}
	}
	return ""
}

// ensureEngine returns the engine binary for a release, building + caching it
// from `git archive <vTAG>` if absent. Returns ok=false if the tag won't build.
func ensureEngine(c *config, rel string) (string, bool) {
	if c.engineOverride != "" {
		return c.engineOverride, true
	}
	tag := "v" + rel
	cached := filepath.Join(c.out, "engines", tag, "cleave")
	if _, err := os.Stat(cached); err == nil {
		return cached, true
	}
	logf("building engine %s (cargo build --release) ...", tag)
	src, err := os.MkdirTemp("", "engine-"+tag+"-")
	if err != nil {
		fatal("mktemp: %v", err)
	}
	defer os.RemoveAll(src)

	ar := exec.Command("git", "-C", c.repo, "archive", "--format=tar", tag)
	var tarBuf bytes.Buffer
	ar.Stdout, ar.Stderr = &tarBuf, os.Stderr
	if err := ar.Run(); err != nil {
		logf("  git archive %s failed: %v", tag, err)
		return "", false
	}
	ex := exec.Command("tar", "-xf", "-", "-C", src)
	ex.Stdin = bytes.NewReader(tarBuf.Bytes())
	if out, err := ex.CombinedOutput(); err != nil {
		logf("  extract %s failed: %v\n%s", tag, err, out)
		return "", false
	}
	// Share a target dir across tag builds so dependency artifacts are reused.
	build := exec.Command("cargo", "build", "--release", "--bin", "cleave")
	build.Dir = src
	build.Env = append(os.Environ(), "CARGO_TARGET_DIR="+filepath.Join(c.out, "engines", ".target"))
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		logf("  build %s FAILED (old toolchain mismatch?) — skipping release", tag)
		return "", false
	}
	binSrc := filepath.Join(c.out, "engines", ".target", "release", "cleave")
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		fatal("mkdir engine cache: %v", err)
	}
	if err := copyFile(binSrc, cached); err != nil {
		fatal("cache engine %s: %v", tag, err)
	}
	logf("  cached engine -> %s", cached)
	return cached, true
}

// buildArtifacts produces a reproducible artifact for every distinct commit any
// pointer references (resolving keys that may predate the commit window).
func buildArtifacts(c *config, pointers map[string]map[string]string, tarCache map[string][]byte) map[string]artifact {
	want := map[string]bool{}
	for _, byRel := range pointers {
		for _, key := range byRel {
			if key != "" {
				want[key] = true
			}
		}
	}
	arts := map[string]artifact{}
	for key := range want {
		cm := resolveCommit(c.traits, key)
		arts[key] = buildArtifact(c.traits, c.out, cm, tarCache)
		logf("built %s  sha256=%s", arts[key].file, arts[key].sha)
	}
	return arts
}

// --- git / commit helpers ---------------------------------------------------

func releaseTags(repo string, n int) []string {
	out := capture(repo, "git", "tag", "-l", "--sort=-version:refname")
	var tags []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		t := strings.TrimSpace(line)
		if len(t) >= 2 && t[0] == 'v' && t[1] >= '0' && t[1] <= '9' {
			tags = append(tags, strings.TrimPrefix(t, "v"))
			if len(tags) == n {
				break
			}
		}
	}
	return tags
}

func traitsCommits(traits string, n int) []commit {
	out := capture(traits, "git", "log", fmt.Sprintf("-n%d", n),
		"--format=%H %h %cd", "--date=format:%Y-%m-%d")
	var commits []commit
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if c, ok := parseCommitLine(line); ok {
			commits = append(commits, c)
		}
	}
	return commits
}

func resolveCommit(traits, ref string) commit {
	out := capture(traits, "git", "show", "-s", "--format=%H %h %cd", "--date=format:%Y-%m-%d", ref)
	c, ok := parseCommitLine(strings.TrimSpace(out))
	if !ok {
		fatal("cannot resolve commit %q", ref)
	}
	return c
}

func parseCommitLine(line string) (commit, bool) {
	f := strings.Fields(line)
	if len(f) != 3 {
		return commit{}, false
	}
	t, _ := time.Parse("2006-01-02", f[2])
	return commit{full: f[0], short: f[1], date: f[2], t: t}, true
}

// floorIndex returns the index of the first candidate NEWER than the floor key:
// commits[:floorIndex] are the commits to (re)consider. A missing/empty floor
// means the whole window is in play.
func floorIndex(commits []commit, floorKey string) int {
	if floorKey == "" {
		return len(commits)
	}
	for i, c := range commits {
		if c.short == floorKey || strings.HasPrefix(c.full, floorKey) {
			return i
		}
	}
	return len(commits) // floor older than the window: consider all of it
}

// --- validation (memoized on tag+commit) ------------------------------------

func validate(traits, engine, rel string, c commit, tarCache map[string][]byte, memo map[string]bool) bool {
	ck := rel + "\t" + c.full
	if v, ok := memo[ck]; ok {
		return v
	}
	tmp, err := os.MkdirTemp("", "traits-"+c.short+"-")
	if err != nil {
		fatal("mktemp: %v", err)
	}
	defer os.RemoveAll(tmp)

	ex := exec.Command("tar", "-xf", "-", "-C", tmp)
	ex.Stdin = bytes.NewReader(archive(traits, c, tarCache))
	if out, err := ex.CombinedOutput(); err != nil {
		fatal("extract %s: %v\n%s", c.short, err, out)
	}
	cmd := exec.Command(engine, "validate")
	cmd.Env = append(os.Environ(), "CLEAVE_TRAITS_DIR="+tmp)
	ok := cmd.Run() == nil
	memo[ck] = ok
	return ok
}

func archive(traits string, c commit, tarCache map[string][]byte) []byte {
	if b, ok := tarCache[c.full]; ok {
		return b
	}
	var buf bytes.Buffer
	cmd := exec.Command("git", "-C", traits, "archive", "--format=tar", c.full)
	cmd.Stdout, cmd.Stderr = &buf, os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("git archive %s: %v", c.short, err)
	}
	b := buf.Bytes()
	tarCache[c.full] = b
	return b
}

func buildArtifact(traits, out string, c commit, tarCache map[string][]byte) artifact {
	xz := exec.Command("xz", "-9", "-T1", "-c")
	xz.Stdin = bytes.NewReader(archive(traits, c, tarCache))
	var buf bytes.Buffer
	xz.Stdout, xz.Stderr = &buf, os.Stderr
	if err := xz.Run(); err != nil {
		fatal("xz %s: %v", c.short, err)
	}
	sum := sha256.Sum256(buf.Bytes())
	file := fmt.Sprintf("%s-%s.tar.xz", c.date, c.short)
	if err := os.WriteFile(filepath.Join(out, file), buf.Bytes(), 0o644); err != nil {
		fatal("write %s: %v", file, err)
	}
	return artifact{key: c.short, file: file, sha: hex.EncodeToString(sum[:]), commit: c.full, date: c.date}
}

// --- manifest render + floor parse ------------------------------------------

func render(validUntil, artifactPrefix string, arts map[string]artifact, tags, channels []string, pointers map[string]map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "manifest_version = 1\n")
	fmt.Fprintf(&b, "valid_until      = %s\n\n", validUntil)

	keys := make([]string, 0, len(arts))
	for k := range arts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := arts[k]
		fmt.Fprintf(&b, "[artifacts.%s]\n", a.key)
		fmt.Fprintf(&b, "file   = %q\n", artifactPrefix+a.file)
		fmt.Fprintf(&b, "sha256 = %q\n", a.sha)
		fmt.Fprintf(&b, "commit = %q\n", a.commit)
		fmt.Fprintf(&b, "date   = %q\n\n", a.date)
	}
	for _, ch := range channels {
		ch = strings.TrimSpace(ch)
		fmt.Fprintf(&b, "[%s]\n", ch)
		for _, rel := range tags {
			if key := pointers[ch][rel]; key != "" {
				fmt.Fprintf(&b, "%q = %q\n", rel, key)
			}
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// parseFloors reads the current pointers from a prior versions.toml. Keys ARE
// short commits in our scheme, so the pointer value is the floor commit; no
// artifacts-table lookup needed. Hand-parses our own rigid format (no TOML dep).
func parseFloors(path string) map[string]map[string]string {
	floors := map[string]map[string]string{}
	data, err := os.ReadFile(path)
	if err != nil {
		return floors
	}
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		// channel tables only (skip [artifacts.*] and the header)
		if section == "" || strings.HasPrefix(section, "artifacts") {
			continue
		}
		rel, key, ok := parseAssign(line)
		if !ok {
			continue
		}
		if floors[section] == nil {
			floors[section] = map[string]string{}
		}
		floors[section][rel] = key
	}
	return floors
}

// parseAssign parses `"lhs" = "rhs"` into unquoted lhs, rhs.
func parseAssign(line string) (string, string, bool) {
	eq := strings.Index(line, "=")
	if eq < 0 {
		return "", "", false
	}
	lhs := strings.Trim(strings.TrimSpace(line[:eq]), `"`)
	rhs := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
	if lhs == "" || rhs == "" {
		return "", "", false
	}
	return lhs, rhs, true
}

// --- memo cache (rel\tcommit\t0|1) ------------------------------------------

func cachePath(out string) string { return filepath.Join(out, ".validate-cache.tsv") }

func loadCache(out string) map[string]bool {
	m := map[string]bool{}
	data, err := os.ReadFile(cachePath(out))
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 3 {
			m[f[0]+"\t"+f[1]] = f[2] == "1"
		}
	}
	return m
}

func saveCache(out string, m map[string]bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := "0"
		if m[k] {
			v = "1"
		}
		fmt.Fprintf(&b, "%s\t%s\n", k, v)
	}
	_ = os.WriteFile(cachePath(out), []byte(b.String()), 0o644)
}

// --- small helpers ----------------------------------------------------------

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

func capture(dir, name string, args ...string) string {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		fatal("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return string(out)
}

func exe(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("%s %s: %v", name, strings.Join(args, " "), err)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
