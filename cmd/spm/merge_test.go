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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/apparmor"
	"github.com/saschagrunert/security-profiles-merger/landlock"
	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

func TestMergeErrors(t *testing.T) {
	t.Parallel()

	invalidFile := writeTemp(t, "not valid json")

	tests := []struct {
		name       string
		args       []string
		stdin      io.Reader
		wantCode   int
		wantStderr string
	}{
		{
			name:       "merge help",
			args:       []string{cmdMerge, flagHelp},
			stdin:      nil,
			wantCode:   0,
			wantStderr: "[files...]",
		},
		{
			name:       "empty stdin",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      strings.NewReader(""),
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "nil stdin",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "empty array",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      strings.NewReader("[]"),
			wantCode:   1,
			wantStderr: testNoInput,
		},
		{
			name:       "missing flags",
			args:       []string{cmdMerge},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "--strategy is required",
		},
		{
			name:       "missing strategy",
			args:       []string{cmdMerge, flagType, typeSeccomp},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "--strategy is required",
		},
		{
			name:       "unknown strategy",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, testBogus},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: "unknown strategy",
		},
		{
			name:       testUnknownType,
			args:       []string{cmdMerge, flagType, testBogus, flagStrategy, strategyIntersect},
			stdin:      strings.NewReader("[{}]"),
			wantCode:   exitUsage,
			wantStderr: testUnknownType,
		},
		{
			name: testUnknownFormat,
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				flagFormat,
				"xml",
			},
			stdin:      nil,
			wantCode:   exitUsage,
			wantStderr: testUnknownFormat,
		},
		{
			name: "nonexistent file",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				"/nonexistent/profile.json",
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name: "invalid JSON seccomp",
			args: []string{
				cmdMerge,
				flagType,
				typeSeccomp,
				flagStrategy,
				strategyIntersect,
				invalidFile,
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name: "invalid JSON apparmor",
			args: []string{
				cmdMerge,
				flagType,
				typeAppArmor,
				flagStrategy,
				strategyUnion,
				invalidFile,
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name: "invalid JSON landlock",
			args: []string{
				cmdMerge,
				flagType,
				typeLandlock,
				flagStrategy,
				strategyIntersect,
				invalidFile,
			},
			stdin:      nil,
			wantCode:   1,
			wantStderr: testErrorColon,
		},
		{
			name:       "stdin too large",
			args:       []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect},
			stdin:      bytes.NewReader(make([]byte, maxInputSize+1)),
			wantCode:   1,
			wantStderr: "exceeds",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			code, _, stderr := runCapture(t, testCase.args, testCase.stdin)

			if code != testCase.wantCode {
				t.Fatalf("exit code = %d, want %d", code, testCase.wantCode)
			}

			if !strings.Contains(stderr, testCase.wantStderr) {
				t.Errorf("stderr = %q, missing %q", stderr, testCase.wantStderr)
			}
		})
	}
}

func TestMergeSeccompInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(seccompJSON(t, testSyscallRead))}

	code := mergeProfiles(
		data, testBogus, formatJSON,
		seccomp.Intersect, seccomp.Union, seccomp.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeSeccompNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		nil, strategyIntersect, formatJSON,
		seccomp.Intersect, seccomp.Union, seccomp.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(apparmorJSON(t, "NET_ADMIN"))}

	code := mergeProfiles(
		data, testBogus, formatJSON,
		apparmor.Intersect, apparmor.Union, apparmor.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeAppArmorNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		nil, strategyIntersect, formatJSON,
		apparmor.Intersect, apparmor.Union, apparmor.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockInvalidStrategy(t *testing.T) {
	t.Parallel()

	data := [][]byte{[]byte(landlockJSON(t, "read_file"))}

	code := mergeProfiles(
		data, testBogus, formatJSON,
		landlock.Intersect, landlock.Union, landlock.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeLandlockNoProfiles(t *testing.T) {
	t.Parallel()

	code := mergeProfiles(
		nil, strategyUnion, formatJSON,
		landlock.Intersect, landlock.Union, landlock.FormatProfile,
		&bytes.Buffer{}, &bytes.Buffer{},
	)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

func TestMergeSeccompIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead, "write"))
	p2 := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 || result.Syscalls[0].Names[0] != testSyscallRead {
		t.Errorf("expected only read syscall, got %v", result.Syscalls)
	}
}

func TestMergeSeccompUnionStdin(t *testing.T) {
	t.Parallel()

	input := "[" + seccompJSON(t, testSyscallRead) + "," +
		seccompJSON(t, "write") + "]"

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyUnion,
	}, strings.NewReader(input))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if names := syscallNames(result.Syscalls); len(names) != 2 {
		t.Errorf("expected 2 syscall names, got %v", names)
	}
}

func TestMergeSeccompHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, seccompJSON(t, testSyscallRead))
	p2 := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "Profile{") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeAppArmorUnionFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	p2 := writeTemp(t, apparmorJSON(t, "SYS_TIME"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyUnion, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %v", result)
	}
}

func TestMergeAppArmorIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN", "SYS_TIME"))
	p2 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 1 {
		t.Errorf("expected 1 capability, got %v", result)
	}
}

func TestMergeLandlockIntersectFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file", "write_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}

	// The second profile does not handle write_file, so it never restricts
	// it, and the first grants it: both rights survive.
	want := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	if !slices.Equal(result.PathRules[0].AccessFS, want) {
		t.Errorf("expected %v, got %v", want, result.PathRules[0].AccessFS)
	}
}

func TestMergeLandlockUnionFiles(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file", "write_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyUnion, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}
}

func TestMergeAppArmorHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	p2 := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeAppArmor, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "caps:") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeLandlockHumanFormat(t *testing.T) {
	t.Parallel()

	p1 := writeTemp(t, landlockJSON(t, "read_file"))
	p2 := writeTemp(t, landlockJSON(t, "read_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeLandlock, flagStrategy, strategyIntersect,
		flagFormat, formatHuman, p1, p2,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	if !strings.Contains(stdout, "read_file") {
		t.Errorf("expected human-readable output, got: %s", stdout)
	}
}

func TestMergeDuplicateStdin(t *testing.T) {
	t.Parallel()

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, "-", "-",
	}, strings.NewReader("["+seccompJSON(t, testSyscallRead)+"]"))

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "stdin") {
		t.Errorf("stderr = %q, missing stdin error", stderr)
	}
}

func TestMergeStdinDash(t *testing.T) {
	t.Parallel()

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, "-",
	}, strings.NewReader("["+
		seccompJSON(t, testSyscallRead)+","+
		seccompJSON(t, testSyscallRead)+"]"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
	}
}

func TestMergeAutoDetectSeccomp(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, seccompJSON(t, testSyscallRead))
	fileB := writeTemp(t, seccompJSON(t, testSyscallRead, "write"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if names := syscallNames(result.Syscalls); len(names) != 2 {
		t.Errorf("expected 2 syscall names, got %v", names)
	}
}

func TestMergeAutoDetectAppArmor(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, apparmorJSON(t, "NET_ADMIN"))
	fileB := writeTemp(t, apparmorJSON(t, "SYS_TIME"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result apparmor.Profile

	unmarshalOutput(t, stdout, &result)

	if result.Capabilities == nil || len(result.Capabilities.AllowedCapabilities) != 2 {
		t.Error("expected 2 capabilities in union")
	}
}

func TestMergeAutoDetectLandlock(t *testing.T) {
	t.Parallel()

	fileA := writeTemp(t, landlockJSON(t, "read_file"))
	fileB := writeTemp(t, landlockJSON(t, "read_file", "write_file"))

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyUnion, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result landlock.Profile

	unmarshalOutput(t, stdout, &result)

	if len(result.HandledAccessFS) != 1 ||
		result.HandledAccessFS[0] != landlock.FSAccessReadFile {
		t.Errorf(
			"expected [read_file] (intersection of handled rights), got %v",
			result.HandledAccessFS,
		)
	}

	if len(result.PathRules) != 1 {
		t.Errorf("expected 1 path rule, got %d", len(result.PathRules))
	}
}

func TestMergeOutputFlag(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	outFile := filepath.Join(t.TempDir(), "output.json")

	code, _, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		"--output", outFile,
		file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	var result specs.LinuxSeccomp

	err = json.Unmarshal(data, &result)
	if err != nil {
		t.Fatalf("unmarshaling output file: %v", err)
	}

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
	}
}

func TestMergeOutputFilePermissions(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	outFile := filepath.Join(t.TempDir(), "output.json")

	code, _, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		"--output", outFile,
		file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	info, err := os.Stat(outFile)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}

	const wantPerm = os.FileMode(0o600)
	if got := info.Mode().Perm(); got != wantPerm {
		t.Errorf("output file permissions = %o, want %o", got, wantPerm)
	}
}

func TestMergeAutoDetectStdin(t *testing.T) {
	t.Parallel()

	profile := seccompJSON(t, testSyscallRead)

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyIntersect,
	}, strings.NewReader("["+profile+","+profile+"]"))

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if len(result.Syscalls) != 1 {
		t.Errorf("expected 1 syscall, got %d", len(result.Syscalls))
	}
}

func TestMergeFileTooLarge(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bigFile := filepath.Join(dir, "big.json")

	err := os.WriteFile(bigFile, make([]byte, maxInputSize+1), 0o600)
	if err != nil {
		t.Fatalf("writing big file: %v", err)
	}

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, bigFile,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "exceeds") {
		t.Errorf("stderr = %q, missing file too large error", stderr)
	}
}

func TestMergeOutputFlagBadPath(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect,
		"--output", "/nonexistent/dir/out.json", file,
	}, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "creating output file") {
		t.Errorf("stderr = %q, missing output file error", stderr)
	}
}

func TestMergeTooManyFiles(t *testing.T) {
	t.Parallel()

	baseArgs := []string{cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect}
	args := make([]string, 0, len(baseArgs)+maxInputFiles+1)
	args = append(args, baseArgs...)

	for idx := range maxInputFiles + 1 {
		args = append(args, fmt.Sprintf("/nonexistent/file_%d.json", idx))
	}

	code, _, stderr := runCapture(t, args, nil)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}

	if !strings.Contains(stderr, "too many") {
		t.Errorf("stderr = %q, missing too many files error", stderr)
	}
}

func TestMergeAutoDetectAmbiguousProfile(t *testing.T) {
	t.Parallel()

	ambiguous := `{"defaultAction":"SCMP_ACT_ERRNO","network":{"allowRaw":true}}`

	fileA := writeTemp(t, ambiguous)
	fileB := writeTemp(t, ambiguous)

	code, stdout, _ := runCapture(t, []string{
		cmdMerge, flagStrategy, strategyIntersect, fileA, fileB,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (seccomp takes priority)", code)
	}

	var result specs.LinuxSeccomp

	unmarshalOutput(t, stdout, &result)

	if result.DefaultAction != specs.ActErrno {
		t.Errorf(
			"expected seccomp detection (SCMP_ACT_ERRNO), got %v",
			result.DefaultAction,
		)
	}
}

func TestMergeFileExactMaxSize(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "exact.json")

	profile := []byte(seccompJSON(t, testSyscallRead))
	content := make([]byte, maxInputSize)

	for idx := range maxInputSize - len(profile) {
		content[idx] = ' '
	}

	copy(content[maxInputSize-len(profile):], profile)

	err := os.WriteFile(file, content, 0o600)
	if err != nil {
		t.Fatalf("writing file: %v", err)
	}

	code, _, stderr := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp, flagStrategy, strategyIntersect, file,
	}, nil)

	if code != 0 {
		t.Fatalf(
			"exit code = %d, want 0 for exactly maxInputSize file; stderr=%s",
			code, stderr,
		)
	}
}

func TestMergeOutputHumanFormat(t *testing.T) {
	t.Parallel()

	file := writeTemp(t, seccompJSON(t, testSyscallRead))
	outFile := filepath.Join(t.TempDir(), "output.txt")

	code, _, _ := runCapture(t, []string{
		cmdMerge, flagType, typeSeccomp,
		flagStrategy, strategyIntersect,
		flagFormat, formatHuman,
		"--output", outFile,
		file,
	}, nil)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}

	if !strings.Contains(string(data), "Profile{") {
		t.Errorf("expected human-readable output in file, got: %s", data)
	}
}

func syscallNames(syscalls []specs.LinuxSyscall) []string {
	var names []string

	for _, sc := range syscalls {
		names = append(names, sc.Names...)
	}

	return names
}
