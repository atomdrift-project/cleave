// yara-update re-pins third-party YARA dependencies to their latest versions.
//
// Usage:
//
//	yara-update YARAForge        # update one dependency
//	yara-update                  # update all (any dir containing a RELEASE file)
//
// Run from the directory containing the per-source subdirectories.
package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// httpClient is shared across all requests with a generous timeout for large downloads.
var httpClient = &http.Client{Timeout: 15 * time.Minute}

// retry calls f up to 4 times with exponential backoff and jitter, logging each failure.
// Delays: ~5s, ~10s, ~20s — total wait up to ~52s before the final attempt.
func retry(f func() error) error {
	var err error
	for i := range 4 {
		if err = f(); err == nil {
			return nil
		}
		if i == 3 {
			break
		}
		base := time.Duration(5<<uint(i)) * time.Second
		wait := base + time.Duration(rand.Int63n(int64(base/2)))
		slog.Warn("retrying after error", "attempt", i+1, "err", err, "wait", wait)
		time.Sleep(wait)
	}
	return err
}

// latestGitHubRelease returns the most recent release tag for a GitHub project
// by following the /releases/latest redirect and extracting the tag from the URL.
func latestGitHubRelease(orgRepo string) (string, error) {
	url := fmt.Sprintf("https://github.com/%s/releases/latest", orgRepo)
	var tag string
	err := retry(func() error {
		resp, err := httpClient.Get(url)
		if err != nil {
			return fmt.Errorf("GET %s: %w", url, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		tag = path.Base(resp.Request.URL.Path)
		return nil
	})
	return tag, err
}

// gitClone clones a repository (shallow) into a temp dir and returns the HEAD commit hash and temp dir path.
// Each retry attempt uses a fresh temp dir; failed dirs are cleaned up before retrying.
func gitClone(repo string) (string, string, error) {
	slog.Info("cloning", "repo", repo)
	var dir string
	if err := retry(func() error {
		tmpdir, err := os.MkdirTemp("", "yara-update-*")
		if err != nil {
			return fmt.Errorf("mktemp: %w", err)
		}
		cmd := exec.Command("git", "clone", "--depth=1", repo, tmpdir)
		cmd.Stderr = os.Stderr
		if err = cmd.Run(); err != nil {
			os.RemoveAll(tmpdir)
			return fmt.Errorf("git clone %s: %w", repo, err)
		}
		dir = tmpdir
		return nil
	}); err != nil {
		return "", "", err
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", dir, fmt.Errorf("git rev-parse HEAD: %w", err)
	}
	return strings.TrimSpace(string(out)), dir, nil
}

// copyFile copies a single file from src to dst, creating dst if needed.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// copyFlat walks src and copies any file whose name matches one of the glob patterns
// directly into dst (no subdirectory structure), equivalent to:
//
//	find src -name "*.yar" -exec cp {} dst \;
func copyFlat(src, dst string, patterns []string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		for _, pat := range patterns {
			if ok, _ := filepath.Match(pat, d.Name()); ok {
				dst := filepath.Join(dst, d.Name())
				slog.Debug("copying", "src", p, "dst", dst)
				return copyFile(p, dst)
			}
		}
		return nil
	})
}

// copyAll recursively copies src into dst, preserving directory structure,
// equivalent to: cp -Rp src/* dst/
func copyAll(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		slog.Debug("copying", "src", p, "dst", target)
		return copyFile(p, target)
	})
}

// downloadYARAForge downloads the full rules zip for a given release and extracts
// packages/full/yara-rules-full.yar into the destination directory.
func downloadYARAForge(rel, dst string) error {
	url := fmt.Sprintf("https://github.com/YARAHQ/yara-forge/releases/download/%s/yara-forge-rules-full.zip", rel)
	slog.Info("downloading", "url", url)

	tmp, err := os.CreateTemp("", "yaraforge-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := retry(func() error {
		if err := tmp.Truncate(0); err != nil {
			return err
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return err
		}
		resp, err := httpClient.Get(url)
		if err != nil {
			return fmt.Errorf("GET %s: %w", url, err)
		}
		defer resp.Body.Close()
		if _, err := io.Copy(tmp, resp.Body); err != nil {
			return fmt.Errorf("copy: %w", err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("flush download: %w", err)
	}

	r, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	const target = "packages/full/yara-rules-full.yar"
	for _, f := range r.File {
		if f.Name != target {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		out, err := os.Create(filepath.Join(dst, "yara-rules-full.yar"))
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			return fmt.Errorf("extract: %w", err)
		}
		return out.Close()
	}
	return fmt.Errorf("%s not found in zip", target)
}

func updateDep(kind string) error {
	slog.Info("updating", "kind", kind)

	if err := os.MkdirAll(kind, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", kind, err)
	}

	var (
		rel    string
		tmpdir string
		err    error
	)

	switch kind {
	case "YARAForge":
		rel, err = latestGitHubRelease("YARAHQ/yara-forge")
		if err != nil {
			return fmt.Errorf("latest release: %w", err)
		}
		slog.Info("found release", "kind", kind, "release", rel)
		if err := downloadYARAForge(rel, kind); err != nil {
			return fmt.Errorf("download YARAForge: %w", err)
		}

	case "huntress":
		rel, tmpdir, err = gitClone("https://github.com/huntresslabs/threat-intel.git")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpdir)
		if err := copyFlat(tmpdir, kind, []string{"*.yar", "*.yara", "*LICENSE*"}); err != nil {
			return err
		}
		for _, f := range []string{"boinc.yar", "defendnot_tool.yar"} {
			p := filepath.Join(kind, f)
			slog.Info("removing broken rule file", "file", p)
			os.Remove(p)
		}

	case "bartblaze":
		rel, tmpdir, err = gitClone("https://github.com/bartblaze/Yara-rules.git")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpdir)
		for _, f := range []string{"LICENSE", "README.md"} {
			if err := copyFile(filepath.Join(tmpdir, f), filepath.Join(kind, f)); err != nil {
				slog.Warn("skipping missing file", "file", f, "err", err)
			}
		}
		if err := copyAll(filepath.Join(tmpdir, "rules"), kind); err != nil {
			return fmt.Errorf("copy rules: %w", err)
		}

	case "JPCERT":
		rel, tmpdir, err = gitClone("https://github.com/JPCERTCC/jpcert-yara.git")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpdir)
		if err := copyFlat(tmpdir, kind, []string{"*.yar", "*.yara", "*LICENSE*", "README*"}); err != nil {
			return err
		}

	case "TTC-CERT":
		rel, tmpdir, err = gitClone("https://github.com/ttc-cert/TTC-CERT-YARA-Rules.git")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpdir)
		if err := copyAll(tmpdir, kind); err != nil {
			return err
		}

	case "elastic":
		rel, tmpdir, err = gitClone("https://github.com/elastic/protections-artifacts.git")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpdir)
		if err := copyFlat(tmpdir, kind, []string{"*.yar", "*.yara", "*LICENSE*"}); err != nil {
			return err
		}

	case "RussianPanda95":
		rel, tmpdir, err = gitClone("https://github.com/RussianPanda95/Yara-Rules.git")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmpdir)
		if err := copyFile(filepath.Join(tmpdir, "README.md"), filepath.Join(kind, "README.md")); err != nil {
			slog.Warn("skipping missing file", "file", "README.md", "err", err)
		}
		if err := copyAll(tmpdir, kind); err != nil {
			return err
		}

	default:
		return fmt.Errorf("unknown kind: %s", kind)
	}

	if err := os.WriteFile(filepath.Join(kind, "RELEASE"), []byte(rel+"\n"), 0o644); err != nil {
		return fmt.Errorf("write RELEASE: %w", err)
	}
	slog.Info("updated", "kind", kind, "release", rel)
	return nil
}

func main() {
	verbose := flag.Bool("v", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))

	cwd, err := os.Getwd()
	if err != nil {
		slog.Error("getwd", "err", err)
		os.Exit(1)
	}
	slog.Info("yara-update starting", "cwd", cwd)

	if flag.NArg() > 0 {
		slog.Info("explicit targets", "kinds", flag.Args())
		for _, kind := range flag.Args() {
			if err := updateDep(kind); err != nil {
				slog.Error("update failed", "kind", kind, "err", err)
				os.Exit(1)
			}
		}
		return
	}

	// No args: update every directory that contains a RELEASE file,
	// or all known deps if none are found (e.g. fresh/empty directory).
	allKinds := []string{"YARAForge", "huntress", "bartblaze", "JPCERT", "TTC-CERT", "elastic", "RussianPanda95"}

	slog.Info("scanning for existing deps", "dir", cwd)
	entries, err := os.ReadDir(".")
	if err != nil {
		slog.Error("reading directory", "err", err)
		os.Exit(1)
	}

	var toUpdate []string
	for _, e := range entries {
		if !e.IsDir() {
			slog.Debug("skipping non-directory", "name", e.Name())
			continue
		}
		releasePath := filepath.Join(e.Name(), "RELEASE")
		if _, err := os.Stat(releasePath); err == nil {
			slog.Info("found existing dep", "kind", e.Name(), "release_file", releasePath)
			toUpdate = append(toUpdate, e.Name())
		} else {
			slog.Debug("skipping directory without RELEASE", "dir", e.Name())
		}
	}

	if len(toUpdate) == 0 {
		slog.Info("no existing deps found, updating all known sources", "kinds", allKinds)
		toUpdate = allKinds
	} else {
		slog.Info("updating existing deps", "kinds", toUpdate)
	}

	var failed bool
	for _, kind := range toUpdate {
		if err := updateDep(kind); err != nil {
			slog.Error("update failed", "kind", kind, "err", err)
			failed = true
		}
	}
	if failed {
		os.Exit(1)
	}
	slog.Info("all updates complete")
}
