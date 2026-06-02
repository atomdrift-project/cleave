// Command manifest-gen builds a trait-update versions.toml from the last few
// cleave engine release tags and the last few cleave-traits commits.
//
// For each candidate traits commit (newest first) it validates the committed
// tree against the current engine (cleave validate); the newest passing commit
// becomes the beta pointer, and the newest passing commit older than the soak
// window becomes the stable pointer. Artifacts are git-archive + xz (reproducible,
// committed-tree-only). It then renders versions.toml and optionally cosign-signs.
//
// Scope (v1): validation runs against ONE engine (--engine). The cross-version
// matrix in docs/UPDATE_DISTRIBUTION.md needs archived prior engine binaries;
// until then every enumerated release key gets the same validated commits, and
// that approximation is logged.
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
	full  string
	short string
	date  string // YYYY-MM-DD, committer date
	t     time.Time
}

type artifact struct {
	key, file, sha, commit, date string
}

func main() {
	traits := flag.String("traits", "../cleave-traits", "path to the cleave-traits git repo")
	repo := flag.String("repo", ".", "path to the cleave (engine) git repo, for release tags")
	engine := flag.String("engine", "./target/release/cleave", "cleave binary used as the validation oracle")
	out := flag.String("out", "dist", "output directory for artifacts + versions.toml")
	nReleases := flag.Int("releases", 2, "number of recent engine release tags to key the manifest by")
	nCommits := flag.Int("commits", 10, "number of recent traits commits to consider")
	soakDays := flag.Int("soak-days", 7, "stable lags beta by at least this many days (time-based soak)")
	channels := flag.String("channels", "stable,beta", "channels to populate, in output order")
	validUntilDays := flag.Int("valid-days", 7, "valid_until = now + this many days")
	noValidate := flag.Bool("no-validate", false, "skip the validate gate (structure only; unsafe)")
	sign := flag.Bool("sign", false, "cosign-sign the rendered versions.toml")
	identity := flag.String("identity", "", "expected signer identity (required with --sign)")
	flag.Parse()

	if *sign && *identity == "" {
		fatal("--sign requires --identity")
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal("mkdir %s: %v", *out, err)
	}

	engineVer := engineVersion(*engine)
	tags := releaseTags(*repo, *nReleases)
	if len(tags) == 0 {
		fatal("no release tags found in %s", *repo)
	}
	commits := traitsCommits(*traits, *nCommits)
	if len(commits) == 0 {
		fatal("no commits found in %s", *traits)
	}
	logf("engine=%s  releases=%v  considering %d traits commits", engineVer, tags, len(commits))

	// Select beta (newest passing) and stable (newest passing older than soak).
	cache := loadCache(*out)
	tarCache := map[string][]byte{}
	cutoff := time.Now().UTC().AddDate(0, 0, -*soakDays)
	var beta, stable *commit
	for i := range commits {
		c := commits[i]
		var ok bool
		if *noValidate {
			ok = true
		} else {
			ok = validate(*traits, *engine, engineVer, c, tarCache, cache)
		}
		logf("  %s %s  validate=%v", c.short, c.date, ok)
		if !ok {
			continue
		}
		if beta == nil {
			beta = &commits[i]
		}
		if stable == nil && !c.t.After(cutoff) {
			stable = &commits[i]
		}
		if beta != nil && stable != nil {
			break
		}
	}
	saveCache(*out, cache)

	if beta == nil {
		fatal("no traits commit passed validation in the last %d", *nCommits)
	}
	if stable == nil {
		logf("no passing commit older than %d days; stable falls back to beta (%s)", *soakDays, beta.short)
		stable = beta
	}
	logf("selected: beta=%s  stable=%s", beta.short, stable.short)

	// Build artifacts for the distinct chosen commits.
	chosen := map[string]*commit{beta.short: beta, stable.short: stable}
	arts := map[string]artifact{}
	for _, c := range chosen {
		a := buildArtifact(*traits, *out, *c, tarCache)
		arts[a.key] = a
		logf("built %s  sha256=%s", a.file, a.sha)
	}

	// Render + optionally sign.
	validUntil := time.Now().UTC().AddDate(0, 0, *validUntilDays).Format("2006-01-02T15:04:05Z")
	chans := strings.Split(*channels, ",")
	manifest := render(validUntil, arts, tags, beta.short, stable.short, chans)
	manifestPath := filepath.Join(*out, "versions.toml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		fatal("write %s: %v", manifestPath, err)
	}
	logf("rendered %s", manifestPath)

	if *sign {
		logf("signing %s as %s (publishes identity to public logs)", manifestPath, *identity)
		run("", "cosign", "sign-blob", "--new-bundle-format", "--yes",
			"--bundle", manifestPath+".sigstore.json", manifestPath)
		logf("signed -> %s.sigstore.json (pin: %s)", manifestPath, *identity)
	}
	logf("done.")
}

// releaseTags returns the most recent N release tags (vX.Y.Z[-rc.N]), stripped
// of the leading "v", to use as manifest release keys.
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
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		t, _ := time.Parse("2006-01-02", f[2])
		commits = append(commits, commit{full: f[0], short: f[1], date: f[2], t: t})
	}
	return commits
}

// validate extracts the committed tree and runs `cleave validate` against it.
// Memoized on (engineVer, commit) so a commit is never validated twice.
func validate(traits, engine, engineVer string, c commit, tarCache map[string][]byte, cache map[string]bool) bool {
	ck := engineVer + "\t" + c.full
	if v, ok := cache[ck]; ok {
		return v
	}
	tmp, err := os.MkdirTemp("", "traits-"+c.short+"-")
	if err != nil {
		fatal("mktemp: %v", err)
	}
	defer os.RemoveAll(tmp)

	tar := archive(traits, c, tarCache)
	extract := exec.Command("tar", "-xf", "-", "-C", tmp)
	extract.Stdin = bytes.NewReader(tar)
	if out, err := extract.CombinedOutput(); err != nil {
		fatal("extract %s: %v\n%s", c.short, err, out)
	}

	cmd := exec.Command(engine, "validate")
	cmd.Env = append(os.Environ(), "CLEAVE_TRAITS_DIR="+tmp)
	err = cmd.Run()
	ok := err == nil
	cache[ck] = ok
	return ok
}

// archive returns the deterministic `git archive` tar bytes for a commit,
// caching them so each commit is archived at most once per run.
func archive(traits string, c commit, tarCache map[string][]byte) []byte {
	if b, ok := tarCache[c.full]; ok {
		return b
	}
	var buf bytes.Buffer
	cmd := exec.Command("git", "-C", traits, "archive", "--format=tar", c.full)
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("git archive %s: %v", c.short, err)
	}
	b := buf.Bytes()
	tarCache[c.full] = b
	return b
}

// buildArtifact xz-compresses the commit's archive (single-thread = reproducible)
// and computes its sha256.
func buildArtifact(traits, out string, c commit, tarCache map[string][]byte) artifact {
	tar := archive(traits, c, tarCache)
	xz := exec.Command("xz", "-9", "-T1", "-c")
	xz.Stdin = bytes.NewReader(tar)
	var buf bytes.Buffer
	xz.Stdout = &buf
	xz.Stderr = os.Stderr
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

// render produces versions.toml: sorted [artifacts.<key>] catalog, then one
// [<channel>] table per channel mapping each release to its pointer key.
func render(validUntil string, arts map[string]artifact, tags []string, betaKey, stableKey string, chans []string) string {
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
		fmt.Fprintf(&b, "file   = %q\n", a.file)
		fmt.Fprintf(&b, "sha256 = %q\n", a.sha)
		fmt.Fprintf(&b, "commit = %q\n", a.commit)
		fmt.Fprintf(&b, "date   = %q\n\n", a.date)
	}

	for _, ch := range chans {
		ch = strings.TrimSpace(ch)
		key := betaKey
		if ch == "stable" {
			key = stableKey
		}
		fmt.Fprintf(&b, "[%s]\n", ch)
		for _, rel := range tags {
			fmt.Fprintf(&b, "%q = %q\n", rel, key)
		}
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

// --- validation memo cache (engineVer\tcommit\t0|1 per line) ----------------

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
	var b strings.Builder
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
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

func engineVersion(engine string) string {
	out, err := exec.Command(engine, "--version").Output()
	if err != nil {
		fatal("%s --version: %v", engine, err)
	}
	return strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
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

func run(dir, name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fatal("%s %s: %v", name, strings.Join(args, " "), err)
	}
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) }

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
