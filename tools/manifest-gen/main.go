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
	"bufio"
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
	headEngine                        string
	artifactPrefix                    string
	engineBins                        []string
	traitsEnv                         string
	validateArgs                      []string
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
	flag.StringVar(&c.headEngine, "head-engine", "", "current/HEAD build used to validate the `latest` pointer (the newest bundle that works for HEAD); empty = no latest validation")
	flag.StringVar(&c.out, "out", "dist", "output directory")
	flag.StringVar(&c.artifactPrefix, "artifact-prefix", "",
		"path prepended to each artifact's `file` in the manifest, relative to the manifest (e.g. \"traits/\")")
	engineBin := flag.String("engine-bin", "cleave",
		"comma-separated cargo bin name(s) to build per tag, tried in order; spans a rename across the tag range (e.g. \"litmus,ascan\")")
	flag.StringVar(&c.traitsEnv, "traits-env", "CLEAVE_TRAITS_DIR",
		"env var set to the extracted checkout when validating (cleave: CLEAVE_TRAITS_DIR; litmus: LITMUS_MODELS_DIR)")
	validateArgs := flag.String("validate-args", "validate",
		"engine subcommand+args used as the oracle (cleave: \"validate\"; litmus: \"validate --skip-traits\")")
	flag.IntVar(&c.nReleases, "releases", 2, "recent engine release tags to key the manifest by")
	flag.IntVar(&c.nCommits, "commits", 8, "recent traits commits to consider (the ceiling; the floor bounds the rest). HEAD/`latest` only ever uses the single newest commit")
	flag.IntVar(&c.soakDays, "soak-days", 7, "stable lags beta by at least this many days")
	flag.IntVar(&c.validDays, "valid-days", 7, "valid_until = now + this many days")
	chans := flag.String("channels", "stable,beta", "channels to populate, in output order")
	flag.BoolVar(&c.noValidate, "no-validate", false, "skip the gate (structure only; unsafe)")
	flag.BoolVar(&c.sign, "sign", false, "cosign-sign the rendered manifest")
	flag.StringVar(&c.identity, "identity", "", "expected signer identity (required with --sign)")
	flag.Parse()
	c.channels = strings.Split(*chans, ",")
	c.validateArgs = strings.Fields(*validateArgs)
	for _, b := range strings.Split(*engineBin, ",") {
		if b = strings.TrimSpace(b); b != "" {
			c.engineBins = append(c.engineBins, b)
		}
	}
	if len(c.engineBins) == 0 {
		fatal("--engine-bin must name at least one cargo bin")
	}

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
	if len(tags) == 0 && c.headEngine == "" {
		fatal("no release tags in %s (and no --head-engine for a latest-only manifest)", c.repo)
	}
	commits := traitsCommits(c.traits, c.nCommits) // newest first
	if len(commits) == 0 {
		fatal("no commits in %s", c.traits)
	}
	floors, _ := parseFloors(filepath.Join(c.out, "versions.toml")) // [channel][release]=key
	memo := loadCache(c.out)
	tarCache := map[string][]byte{}
	cutoff := time.Now().UTC().AddDate(0, 0, -c.soakDays)
	logf("releases=%v  considering up to %d traits commits", tags, len(commits))

	// HEAD anchor, FIRST: `latest` must point at the single newest traits commit
	// validated by the current engine. We never walk back to an older commit for
	// HEAD — if the newest commit fails, the whole release fails (loudly, with the
	// engine's exact output). Doing this before any per-release engine build means
	// a broken HEAD aborts instantly instead of after minutes of cargo builds.
	// Older release tags are unaffected: they stay frozen on the traits they
	// already validated.
	latest := ""
	if c.headEngine != "" {
		latest = anchorHead(c, commits[0], tarCache, memo)
		saveCache(c.out, memo)
	} else {
		logf("  (no --head-engine: 'latest' left empty; HEAD/dev clients have no fallback)")
	}

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
		// First pass: independent per-channel selection (newest passing commit,
		// bounded below by that channel's floor; keep the floor if nothing newer
		// qualifies — it's already known-good).
		sel := map[string]string{}
		for _, ch := range c.channels {
			ch = strings.TrimSpace(ch)
			floor := floors[ch][rel]
			cand := commits[:floorIndex(commits, floor)] // strictly newer than the floor
			s := selectPointer(c, enginePath, rel, ch, cand, cutoff, tarCache, memo)
			if s == "" {
				s = floor
			}
			sel[ch] = s
			logf("  %s/%s -> %s (floor=%q, %d candidates)", rel, ch, orNone(s), floor, len(cand))
		}
		// Cross-channel fallback, applied after all channels are computed so it
		// never depends on channel order: a fresh manifest with no soaked stable
		// yet pins stable to whatever beta resolved to.
		if s, ok := sel["stable"]; ok && s == "" {
			sel["stable"] = sel["beta"]
			logf("  %s/stable -> %s (fallback to beta)", rel, orNone(sel["stable"]))
		}
		for _, ch := range c.channels {
			ch = strings.TrimSpace(ch)
			pointers[ch][rel] = sel[ch]
		}
	}
	// Refuse to publish a manifest whose newest release has no pointer in a
	// configured channel: the current engine either wouldn't build or rejected
	// every candidate, and shipping it would strand clients on that release with
	// no model. Older releases may legitimately stay empty (frozen at a prior
	// floor or aged out), so this guards only the newest tag.
	if len(tags) > 0 {
		newest := tags[0]
		for _, ch := range c.channels {
			ch = strings.TrimSpace(ch)
			if pointers[ch][newest] == "" {
				fatal("channel %q has no pointer for newest release %s: engine unbuildable or no candidate passed validation — refusing to publish", ch, newest)
			}
		}
	}

	saveCache(c.out, memo)

	arts := buildArtifacts(c, pointers, latest, tarCache)
	validUntil := time.Now().UTC().AddDate(0, 0, c.validDays).Format("2006-01-02T15:04:05Z")
	manifest := render(validUntil, latest, c.artifactPrefix, arts, tags, c.channels, pointers)
	path := filepath.Join(c.out, "versions.toml")
	if err := os.WriteFile(path, []byte(manifest), 0o644); err != nil {
		fatal("write %s: %v", path, err)
	}
	logf("rendered %s", path)

	if c.sign {
		// Pause when interactive so the operator triggers sigstore auth only when
		// ready — the device/browser flow has a short TTL, and the build+validate
		// phase above can take minutes.
		if isInteractive() {
			fmt.Fprintf(os.Stderr,
				"\nReady to sign %s as %s.\nThis starts sigstore auth and PUBLISHES this identity to public transparency logs.\nPress Enter to sign (Ctrl-C to abort)... ",
				path, c.identity)
			_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
		}
		logf("signing %s as %s", path, c.identity)
		// Pass the terminal through so cosign uses the interactive browser flow
		// (with a TTY) rather than the device-code flow.
		cmd := exec.Command("cosign", "sign-blob", "--new-bundle-format", "--yes",
			"--bundle", path+".sigstore.json", path)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fatal("cosign sign-blob: %v", err)
		}
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
		ok := c.noValidate || validate(c, engine, rel, cm, tarCache, memo)
		logf("    %s/%s try %s (%s) -> %s", rel, ch, cm.short, cm.date, passWord(ok))
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
	dir := filepath.Join(c.out, "engines", tag)
	// A prior run may have cached the binary under any candidate bin name.
	for _, bin := range c.engineBins {
		cached := filepath.Join(dir, bin)
		if _, err := os.Stat(cached); err == nil {
			return cached, true
		}
	}
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
	// MUST be absolute: cargo runs with cwd=src (the temp checkout), so a relative
	// CARGO_TARGET_DIR would resolve under the temp dir, not our output.
	targetDir, err := filepath.Abs(filepath.Join(c.out, "engines", ".target"))
	if err != nil {
		fatal("resolve target dir: %v", err)
	}
	// The engine bin was renamed across releases (litmus -> ascan), so any given
	// tag builds under exactly one candidate name. Try each in order; the first
	// that builds wins. Print a one-line reason per failed attempt so a genuine
	// breakage is never silently mistaken for "wrong bin name for this tag".
	for _, bin := range c.engineBins {
		logf("building engine %s --bin %s (cargo build --release) ...", tag, bin)
		build := exec.Command("cargo", "build", "--release", "--bin", bin)
		build.Dir = src
		build.Env = append(os.Environ(), "CARGO_TARGET_DIR="+targetDir)
		if out, err := build.CombinedOutput(); err != nil {
			logf("  build %s --bin %s failed: %s", tag, bin, briefErr(out))
			continue
		}
		cached := filepath.Join(dir, bin)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatal("mkdir engine cache: %v", err)
		}
		if err := copyFile(filepath.Join(targetDir, "release", bin), cached); err != nil {
			fatal("cache engine %s: %v", tag, err)
		}
		logf("  cached engine -> %s", cached)
		return cached, true
	}
	logf("  build %s FAILED for all candidate bins %v — skipping release", tag, c.engineBins)
	return "", false
}

// buildArtifacts produces a reproducible artifact for every distinct commit any
// pointer references (resolving keys that may predate the commit window).
func buildArtifacts(c *config, pointers map[string]map[string]string, latest string, tarCache map[string][]byte) map[string]artifact {
	want := map[string]bool{}
	for _, byRel := range pointers {
		for _, key := range byRel {
			if key != "" {
				want[key] = true
			}
		}
	}
	if latest != "" {
		want[latest] = true
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
	// versionsort.suffix demotes prereleases so the final release outranks its
	// own rc/beta tags; without it git sorts "v2.0.0-rc.5" ABOVE "v2.0.0" and
	// the real release falls out of the top-n window. selectReleaseTags also
	// skips prereleases outright — stable must never pin to an rc.
	out := capture(repo, "git", "-c", "versionsort.suffix=-rc",
		"tag", "-l", "--sort=-version:refname")
	return selectReleaseTags(out, n)
}

// selectReleaseTags filters newest-first `git tag -l` output to the first n
// stable release tags: those shaped like "v<digit>…" with no prerelease suffix
// ("-rc", "-beta", …), returned without the leading "v".
func selectReleaseTags(gitOutput string, n int) []string {
	var tags []string
	for _, line := range strings.Split(strings.TrimSpace(gitOutput), "\n") {
		t := strings.TrimSpace(line)
		if len(t) >= 2 && t[0] == 'v' && t[1] >= '0' && t[1] <= '9' &&
			!strings.Contains(t, "-") {
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

func validate(cfg *config, engine, rel string, c commit, tarCache map[string][]byte, memo map[string]bool) bool {
	ck := rel + "\t" + c.full
	if v, ok := memo[ck]; ok {
		return v
	}
	ok, output := runValidate(cfg, engine, c, tarCache)
	if !ok {
		// Never let a rejection be a silent "fail": print the engine's own error,
		// attributed to the (release, commit) under test and quoted as a block.
		logf("    %s rejects %s (%s):\n%s", rel, c.short, c.date, indentOutput(output))
	}
	memo[ck] = ok
	return ok
}

// runValidate extracts the commit's traits tree and runs the engine's validate
// oracle against it, returning whether it passed and the engine's combined
// stdout+stderr so a failure can be reported verbatim. Not memoized — callers
// decide whether to cache the boolean.
func runValidate(cfg *config, engine string, c commit, tarCache map[string][]byte) (bool, string) {
	tmp, err := os.MkdirTemp("", "checkout-"+c.short+"-")
	if err != nil {
		fatal("mktemp: %v", err)
	}
	defer os.RemoveAll(tmp)

	ex := exec.Command("tar", "-xf", "-", "-C", tmp)
	ex.Stdin = bytes.NewReader(archive(cfg.traits, c, tarCache))
	if out, err := ex.CombinedOutput(); err != nil {
		fatal("extract %s: %v\n%s", c.short, err, out)
	}
	cmd := exec.Command(engine, cfg.validateArgs...)
	cmd.Env = append(os.Environ(), cfg.traitsEnv+"="+tmp)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out)
}

// anchorHead validates the single newest traits commit against the current
// (HEAD) engine and returns it as the `latest` pointer. If it fails, the entire
// run aborts with the engine's exact output — we deliberately do NOT walk back to
// an older commit, so a broken HEAD never ships and is never masked by a stale
// pointer.
func anchorHead(c *config, newest commit, tarCache map[string][]byte, memo map[string]bool) string {
	if c.noValidate {
		logf("  HEAD/latest -> %s (%s) [validation skipped: --no-validate]", newest.short, newest.date)
		return newest.short
	}
	ok, output := runValidate(c, c.headEngine, newest, tarCache)
	memo["HEAD\t"+newest.full] = ok
	if !ok {
		fatal("HEAD engine rejects the newest traits commit %s (%s) — refusing to publish.\n"+
			"  `latest` must point at the newest commit; we do not fall back to an older one.\n"+
			"  Fix or revert the breaking traits commit, then re-run.\n"+
			"  ── exact `%s %s` output ──\n%s",
			newest.short, newest.date, filepath.Base(c.headEngine),
			strings.Join(c.validateArgs, " "), indentOutput(output))
	}
	logf("  HEAD/latest -> %s (%s) PASS", newest.short, newest.date)
	return newest.short
}

// indentOutput quotes captured engine output as an indented block for the log,
// trimming trailing blank lines. Returns a clear placeholder when the engine
// printed nothing (so "rejected with no output" is never mistaken for a bug here).
func indentOutput(s string) string {
	if strings.TrimSpace(s) == "" {
		return "      | (engine produced no output)"
	}
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("      | ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
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
	// zstd (single-thread = deterministic) for parity with litmus/azoth bundles.
	z := exec.Command("zstd", "-19", "-c")
	z.Stdin = bytes.NewReader(archive(traits, c, tarCache))
	var buf bytes.Buffer
	z.Stdout, z.Stderr = &buf, os.Stderr
	if err := z.Run(); err != nil {
		fatal("zstd %s: %v", c.short, err)
	}
	sum := sha256.Sum256(buf.Bytes())
	file := fmt.Sprintf("%s-%s.tar.zst", c.date, c.short)
	if err := os.WriteFile(filepath.Join(out, file), buf.Bytes(), 0o644); err != nil {
		fatal("write %s: %v", file, err)
	}
	return artifact{key: c.short, file: file, sha: hex.EncodeToString(sum[:]), commit: c.full, date: c.date}
}

// --- manifest render + floor parse ------------------------------------------

func render(validUntil, latest, artifactPrefix string, arts map[string]artifact, tags, channels []string, pointers map[string]map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "manifest_version = 1\n")
	fmt.Fprintf(&b, "valid_until      = %s\n", validUntil)
	if latest != "" {
		fmt.Fprintf(&b, "latest           = %q\n", latest)
	}
	b.WriteString("\n")

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

	// [upgrade]: releases behind the NEWEST RELEASE's traits pointer — i.e. a newer
	// released cleave supports rules this one can't. Measured relative to the newest
	// RELEASE tag, never to `latest`/HEAD, so we never tell anyone to upgrade to an
	// unreleased dev build. Value = the release version to upgrade to. The newest
	// release is never flagged (nothing released is ahead of it).
	if len(tags) > 1 {
		newest := tags[0]
		if newestPtr := pointers["stable"][newest]; newestPtr != "" {
			var behind []string
			for _, rel := range tags[1:] {
				if k := pointers["stable"][rel]; k != "" && k != newestPtr {
					behind = append(behind, rel)
				}
			}
			if len(behind) > 0 {
				b.WriteString("[upgrade]\n")
				for _, rel := range behind {
					fmt.Fprintf(&b, "%q = %q\n", rel, newest)
				}
				b.WriteString("\n")
			}
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// parseFloors reads the current pointers from a prior versions.toml. Keys ARE
// short commits in our scheme, so the pointer value is the floor commit; no
// artifacts-table lookup needed. Hand-parses our own rigid format (no TOML dep).
func parseFloors(path string) (map[string]map[string]string, string) {
	floors := map[string]map[string]string{}
	latestFloor := ""
	data, err := os.ReadFile(path)
	if err != nil {
		return floors, latestFloor
	}
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		// Top-level (pre-table) keys: capture `latest = "<key>"` as its floor.
		if section == "" {
			if lhs, rhs, ok := parseAssign(line); ok && lhs == "latest" {
				latestFloor = rhs
			}
			continue
		}
		if strings.HasPrefix(section, "artifacts") {
			continue // skip [artifacts.*]
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
	return floors, latestFloor
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

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// isInteractive reports whether stdin is a terminal (so a human is present to
// complete the signing auth). Stdlib-only: no x/term dependency.
func isInteractive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// briefErr reduces captured build output to a single line: the first cargo
// "error…" line (e.g. `error: no bin target named litmus`), else the last
// non-empty line.
func briefErr(out []byte) string {
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	for _, l := range lines {
		if s := strings.TrimSpace(l); strings.HasPrefix(s, "error") {
			return s
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			return s
		}
	}
	return "(no build output)"
}

func passWord(ok bool) string {
	if ok {
		return "PASS"
	}
	return "fail"
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
