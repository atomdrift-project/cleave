package main

import (
	"reflect"
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
