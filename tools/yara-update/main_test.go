package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// rulePaths lists every copied file relative to root, so a case-duplicate shows
// up as an extra entry rather than being masked by the filesystem.
func rulePaths(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		out = append(out, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Upstream ships Zharkbot.yar and zharkbot.yar — byte identical, both defining
// `rule ZharkBot`. Copying both makes the checkout differ by platform, which
// breaks reproducibility of the compiled artifacts committed alongside it.
func TestCopyAllCollapsesCaseDuplicates(t *testing.T) {
	src := t.TempDir()
	// Probe the filesystem rather than the OS: a macOS run with TMPDIR on a
	// case-sensitive volume can exercise this, and only a filesystem that can
	// hold both names is able to stage the collision at all.
	write(t, filepath.Join(src, "probe", "A"), "")
	write(t, filepath.Join(src, "probe", "a"), "")
	if probes := rulePaths(t, filepath.Join(src, "probe")); len(probes) < 2 {
		t.Skip("needs a case-sensitive filesystem to stage the collision")
	}
	if err := os.RemoveAll(filepath.Join(src, "probe")); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	write(t, filepath.Join(src, "ZharkBot", "Zharkbot.yar"), "rule ZharkBot {}\n")
	write(t, filepath.Join(src, "ZharkBot", "zharkbot.yar"), "rule ZharkBot {}\n")
	write(t, filepath.Join(src, "ZharkBot", "other.yar"), "rule Other {}\n")

	if err := copyAll(src, dst); err != nil {
		t.Fatalf("copyAll: %v", err)
	}

	got := rulePaths(t, dst)
	if len(got) != 2 {
		t.Fatalf("copied %v, want exactly one zharkbot variant plus other.yar", got)
	}
	var zhark int
	for _, p := range got {
		if strings.EqualFold(filepath.Base(p), "zharkbot.yar") {
			zhark++
		}
	}
	if zhark != 1 {
		t.Errorf("copied %d zharkbot variants, want 1 (%v)", zhark, got)
	}
}

// A file already in the destination must keep its name: renaming it into its
// own case-variant would show up as a delete+add in git on every update.
func TestCopyAllKeepsExistingCase(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	write(t, filepath.Join(src, "ZharkBot", "Zharkbot.yar"), "rule ZharkBot { /* new */ }\n")
	write(t, filepath.Join(dst, "ZharkBot", "zharkbot.yar"), "rule ZharkBot { /* old */ }\n")

	if err := copyAll(src, dst); err != nil {
		t.Fatalf("copyAll: %v", err)
	}

	got := rulePaths(t, dst)
	if len(got) != 1 {
		t.Fatalf("destination holds %v, want the single pre-existing name", got)
	}
	if filepath.Base(got[0]) != "zharkbot.yar" {
		t.Errorf("destination file is %q, want the pre-existing %q", got[0], "zharkbot.yar")
	}
	body, err := os.ReadFile(filepath.Join(dst, got[0]))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "new") {
		t.Errorf("content not refreshed: %q", body)
	}
}
