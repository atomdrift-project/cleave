package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSelectReleaseTags(t *testing.T) {
	// Newest-first output as produced by
	// `git -c versionsort.suffix=-rc tag -l --sort=-version:refname`:
	// the final release sorts above its own rc tags.
	sorted := "v2.0.0\nv2.0.0-rc.5\nv2.0.0-rc.4\nv1.4.0\nv1.3.1\ndelete\n1.2.0\nvv1.1.0\n"

	tests := []struct {
		name      string
		gitOutput string
		n         int
		want      []string
	}{
		{
			name:      "prereleases skipped, real release wins the window",
			gitOutput: sorted,
			n:         2,
			want:      []string{"2.0.0", "1.4.0"},
		},
		{
			name:      "n larger than available stable tags",
			gitOutput: sorted,
			n:         10,
			want:      []string{"2.0.0", "1.4.0", "1.3.1"},
		},
		{
			name:      "only prereleases yields nothing for stable",
			gitOutput: "v3.0.0-rc.2\nv3.0.0-rc.1\n",
			n:         2,
			want:      nil,
		},
		{
			name:      "non-version tags ignored",
			gitOutput: "latest\nstable\ndelete\nvv1.1.0\n1.2.0\n",
			n:         2,
			want:      nil,
		},
		{
			name:      "empty output",
			gitOutput: "",
			n:         2,
			want:      nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := selectReleaseTags(tc.gitOutput, tc.n)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("selectReleaseTags(%q, %d) = %v, want %v",
					tc.gitOutput, tc.n, got, tc.want)
			}
		})
	}
}

func TestArtifactNameIsContentAddressed(t *testing.T) {
	sha := "a37b69b53e920017d9f8afad3cf9810465402fb347c61e968a98cfe9b66743bf"
	got := artifactName("2026-10-07", "a8f1b0916c", sha)
	if got != "2026-10-07-a8f1b0916c-a37b69b53e920017.tar.zst" {
		t.Errorf("artifactName = %q", got)
	}
	a := artifact{key: "a8f1b0916c", file: got, sha: sha, date: "2026-10-07"}
	if !contentAddressed(a) {
		t.Error("a hash-named artifact is not recognised as content-addressed")
	}
	// The 2026-10-07 shape: same commit, name without its hash. Not reusable by
	// name, because the name never fixed the bytes.
	legacy := a
	legacy.file = "2026-10-07-a8f1b0916c.tar.zst"
	if contentAddressed(legacy) {
		t.Error("a commit-named artifact was treated as content-addressed")
	}
	// A name whose hash does not match the recorded sha is not trusted either.
	wrong := a
	wrong.sha = "94b4575b6e51bdcc04d0b9d66ed7991e3f53f6536b8ea0d2afa974b92bdc1ca6"
	if contentAddressed(wrong) {
		t.Error("an artifact whose name disagrees with its sha was trusted")
	}
}

// parseArtifacts must read back exactly what render writes, prefix stripped,
// since buildArtifacts hands reused entries straight back to render.
func TestParseArtifactsRoundTrip(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	arts := map[string]artifact{"a8f1b0916c": {
		key: "a8f1b0916c", file: artifactName("2026-10-07", "a8f1b0916c", sha),
		sha: sha, commit: strings.Repeat("c", 40), date: "2026-10-07",
	}}
	manifest := render("2026-10-14T00:00:00Z", "a8f1b0916c", "traits/", arts,
		[]string{"2.12.0"}, []string{"stable"}, map[string]map[string]string{"stable": {"2.12.0": "a8f1b0916c"}})
	path := filepath.Join(t.TempDir(), "versions.toml")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := parseArtifacts(path); !reflect.DeepEqual(got, arts) {
		t.Errorf("round trip:\n got %+v\nwant %+v\nmanifest:\n%s", got, arts, manifest)
	}
	if floors, _ := parseFloors(path); floors["stable"]["2.12.0"] != "a8f1b0916c" {
		t.Errorf("floors lost in the same manifest: %v", floors)
	}
}

// A published content-addressed artifact is reused without touching git or
// zstd: --traits points nowhere, so any rebuild attempt would fatal.
func TestBuildArtifactsReusesPublished(t *testing.T) {
	sha := strings.Repeat("ef", 32)
	prev := artifact{key: "a8f1b0916c", file: artifactName("2026-10-07", "a8f1b0916c", sha),
		sha: sha, commit: strings.Repeat("c", 40), date: "2026-10-07"}
	c := &config{traits: filepath.Join(t.TempDir(), "no-such-repo"), out: t.TempDir()}
	got := buildArtifacts(c, map[string]map[string]string{"stable": {"2.12.0": prev.key}}, prev.key,
		map[string][]byte{}, map[string]artifact{prev.key: prev})
	if got[prev.key] != prev {
		t.Errorf("reused artifact = %+v, want %+v", got[prev.key], prev)
	}
}

// A commit-named (pre-content-addressing) published artifact is rebuilt once,
// under a name carrying its hash, with that hash matching the bytes written.
func TestBuildArtifactsRebuildsLegacyNames(t *testing.T) {
	traits := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", traits}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(traits, "trait.yaml"), []byte("id: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-q", "-m", "traits")
	cm := resolveCommit(traits, "HEAD")

	legacy := artifact{key: cm.short, file: cm.date + "-" + cm.short + ".tar.zst",
		sha: strings.Repeat("0", 64), commit: cm.full, date: cm.date}
	out := t.TempDir()
	got := buildArtifacts(&config{traits: traits, out: out},
		map[string]map[string]string{"stable": {"2.12.0": cm.short}}, "",
		map[string][]byte{}, map[string]artifact{cm.short: legacy})[cm.short]

	if !contentAddressed(got) || got.file == legacy.file {
		t.Fatalf("legacy artifact not renamed by content: %+v", got)
	}
	data, err := os.ReadFile(filepath.Join(out, got.file))
	if err != nil {
		t.Fatalf("rebuilt bundle not written: %v", err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != got.sha {
		t.Error("recorded sha does not match the bundle's bytes")
	}
}
