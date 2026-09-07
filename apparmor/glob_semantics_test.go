/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apparmor_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
)

func fsProfile(rules *apparmor.FilesystemRules) *apparmor.Profile {
	return &apparmor.Profile{
		Executable:   nil,
		Filesystem:   rules,
		Network:      nil,
		Capabilities: nil,
	}
}

func execProfile(paths ...string) *apparmor.Profile {
	return &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: paths,
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}
}

func readOnly(paths ...string) *apparmor.Profile {
	return fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  paths,
		WriteOnlyPaths: nil,
		ReadWritePaths: nil,
	})
}

func readWrite(paths ...string) *apparmor.Profile {
	return fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  nil,
		WriteOnlyPaths: nil,
		ReadWritePaths: paths,
	})
}

func mergeFs(
	t *testing.T,
	mergeFn func(...*apparmor.Profile) (*apparmor.Profile, error),
	profiles ...*apparmor.Profile,
) *apparmor.FilesystemRules {
	t.Helper()

	result, err := mergeFn(profiles...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Filesystem == nil {
		return &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		}
	}

	return result.Filesystem
}

func TestUnionKeepsBroaderGlob(t *testing.T) {
	t.Parallel()

	// "/etc/*" must not prune "/etc/**": matching one pattern string against
	// the other pattern's regex says nothing about language inclusion.
	for _, order := range [][]*apparmor.Profile{
		{readWrite("/etc/*"), readWrite("/etc/**")},
		{readWrite("/etc/**"), readWrite("/etc/*")},
		{readWrite(), readWrite("/etc/*", "/etc/**")},
	} {
		got := mergeFs(t, apparmor.Union, order...).ReadWritePaths
		if want := []string{"/etc/*", "/etc/**"}; !slices.Equal(got, want) {
			t.Errorf("Union rw = %v, want %v", got, want)
		}
	}

	got := mergeFs(t, apparmor.Union, readWrite("/etc/*"), readOnly("/etc/**"))
	if !slices.Equal(got.ReadWritePaths, []string{"/etc/*"}) ||
		!slices.Equal(got.ReadOnlyPaths, []string{"/etc/**"}) {
		t.Errorf("Union = %s, want rw:/etc/* and r:/etc/**", got)
	}
}

func TestIntersectDoubleStarNarrowsSamePrefix(t *testing.T) {
	t.Parallel()

	got := mergeFs(
		t, apparmor.Intersect, readOnly("/etc/**"), readOnly("/etc/*.conf"),
	).ReadOnlyPaths
	if want := []string{"/etc/*.conf"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}

	result, err := apparmor.Intersect(execProfile("/etc/**"), execProfile("/etc/*"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Executable.AllowedExecutables; !slices.Equal(got, []string{"/etc/*"}) {
		t.Errorf("Intersect exec = %v, want [/etc/*]", got)
	}
}

func TestEscapedLiteralMatchesAsFileName(t *testing.T) {
	t.Parallel()

	// "/etc/\*" names the single file "/etc/*", which "?" covers and "??"
	// does not.
	got := mergeFs(t, apparmor.Intersect, readOnly(`/etc/\*`), readOnly("/etc/??")).ReadOnlyPaths
	if len(got) != 0 {
		t.Errorf("Intersect with ?? = %v, want none", got)
	}

	got = mergeFs(t, apparmor.Intersect, readOnly(`/etc/\*`), readOnly("/etc/?")).ReadOnlyPaths
	if want := []string{`/etc/\*`}; !slices.Equal(got, want) {
		t.Errorf("Intersect with ? = %v, want %v", got, want)
	}

	got = mergeFs(t, apparmor.Union, readOnly(`/etc/\*`), readOnly("/etc/??")).ReadOnlyPaths
	if want := []string{"/etc/??", `/etc/\*`}; !slices.Equal(got, want) {
		t.Errorf("Union = %v, want %v", got, want)
	}
}

func TestClassWithMultibyteMember(t *testing.T) {
	t.Parallel()

	got := mergeFs(
		t,
		apparmor.Intersect,
		readOnly("/tmp/[é]"),
		readOnly("/tmp/é", "/tmp/Ã"),
	).ReadOnlyPaths
	if want := []string{"/tmp/é"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}
}

func TestTrailingSlashDistinguishesDirectoryRules(t *testing.T) {
	t.Parallel()

	got := mergeFs(t, apparmor.Union, readOnly("/var/log/"), readOnly("/var/log/**")).ReadOnlyPaths
	if want := []string{"/var/log/", "/var/log/**"}; !slices.Equal(got, want) {
		t.Errorf("Union = %v, want %v", got, want)
	}

	profile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/var/log/"},
		WriteOnlyPaths: nil,
		ReadWritePaths: []string{"/var/log"},
	})

	err := apparmor.Validate(profile)
	if err != nil {
		t.Errorf("Validate rejected distinct file and directory rules: %v", err)
	}

	diff, err := apparmor.Diff(readOnly("/var/log/"), readOnly("/var/log"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if diff.Equal {
		t.Error("Diff treats /var/log/ and /var/log as equal")
	}

	got = mergeFs(
		t,
		apparmor.Intersect,
		readOnly("/var/log//"),
		readOnly("/var/log/"),
	).ReadOnlyPaths
	if want := []string{"/var/log/"}; !slices.Equal(got, want) {
		t.Errorf("Intersect = %v, want %v", got, want)
	}
}

func TestStarRequiresOneCharacterAtComponentStart(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		literal string
		glob    string
		matches bool
	}{
		{"root not matched by /*", "/", "/*", false},
		{"directory not matched by its **", "/etc/", "/etc/**", false},
		{"directory not matched by its *", "/etc/", "/etc/*", false},
		{"file matched by **", "/etc/x", "/etc/**", true},
		{"nested file matched by **", "/etc/a/b", "/etc/**", true},
		{"file matched by *", "/etc/x", "/etc/*", true},
		{"star mid component may be empty", "/etc/x", "/etc/x*", true},
		{"double star mid component may be empty", "/etc/x", "/etc/x**", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := mergeFs(
				t,
				apparmor.Intersect,
				readOnly(test.literal),
				readOnly(test.glob),
			).ReadOnlyPaths

			if matched := len(got) == 1; matched != test.matches {
				t.Errorf(
					"%q vs %q: matched = %v, want %v",
					test.literal,
					test.glob,
					matched,
					test.matches,
				)
			}
		})
	}
}

func TestOversizeGlobDroppedOnIntersection(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 4096) + "/*"

	for _, right := range []*apparmor.Profile{readOnly(long), readOnly("/**")} {
		if got := mergeFs(
			t,
			apparmor.Intersect,
			readOnly(long),
			right,
		).ReadOnlyPaths; len(
			got,
		) != 0 {
			t.Errorf("Intersect kept oversize glob: %d entries", len(got))
		}
	}

	exec := execProfile(long)

	result, err := apparmor.Intersect(exec, exec)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result.Executable.AllowedExecutables; len(got) != 0 {
		t.Errorf("Intersect kept oversize executable glob: %v", got)
	}

	if got := mergeFs(
		t,
		apparmor.Union,
		readOnly(long),
		readOnly("/**"),
	).ReadOnlyPaths; len(
		got,
	) != 2 {
		t.Errorf("Union dropped oversize glob: %v", got)
	}
}

func TestValidateNormalizesPathsForDuplicateChecks(t *testing.T) {
	t.Parallel()

	profile := fsProfile(&apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{"/etc/passwd"},
		WriteOnlyPaths: nil,
		ReadWritePaths: []string{"/etc//passwd"},
	})

	err := apparmor.Validate(profile)
	if !errors.Is(err, apparmor.ErrDuplicatePath) {
		t.Errorf("Validate = %v, want ErrDuplicatePath", err)
	}
}

func TestValidateStrictNormalizesExecutablePaths(t *testing.T) {
	t.Parallel()

	profile := execProfile("/bin/sh", "/bin//sh")

	err := apparmor.ValidateStrict(profile)
	if !errors.Is(err, apparmor.ErrDuplicateExecutablePath) {
		t.Errorf("ValidateStrict = %v, want ErrDuplicateExecutablePath", err)
	}
}
