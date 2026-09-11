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
	"fmt"
	"io"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/apparmor"
	"sigs.k8s.io/security-profiles-merger/landlock"
	"sigs.k8s.io/security-profiles-merger/seccomp"
)

// validateMode selects which validation a profile kind runs.
type validateMode int

const (
	// modeDefault runs the checks the merge path applies.
	modeDefault validateMode = iota
	// modeStrict adds the checks for user-authored profiles and rejects
	// unknown JSON fields.
	modeStrict
	// modeArtifact runs the checks runtimes apply to untrusted artifacts.
	modeArtifact
)

// profileKind wires one profile type into the merge, diff, and validate
// commands.
type profileKind struct {
	name     string
	merge    func(data [][]byte, strategy, format string, stdout, stderr io.Writer) int
	diff     func(data [][]byte, format string, stdout, stderr io.Writer) int
	validate func(data [][]byte, mode validateMode, format string, stdout, stderr io.Writer) int
}

// kindOps holds the package functions of one profile type. validateArtifact
// is nil for types without artifact validation.
type kindOps[T any, D equalChecker] struct {
	intersect        func(...*T) (*T, error)
	union            func(...*T) (*T, error)
	validate         func(*T) error
	validateStrict   func(*T) error
	validateArtifact func(*T) error
	format           func(*T) string
	diff             func(*T, *T) (*D, error)
	formatDiff       func(*D) string
}

// checker returns the validation function for a mode. The second result is
// false when the type has no validation for the mode.
func (ops kindOps[T, D]) checker(mode validateMode) (func(*T) error, bool) {
	switch mode {
	case modeStrict:
		return ops.validateStrict, true
	case modeArtifact:
		return ops.validateArtifact, ops.validateArtifact != nil
	case modeDefault:
		return ops.validate, true
	}

	return ops.validate, true
}

func newKind[T any, D equalChecker](name string, ops kindOps[T, D]) profileKind {
	return profileKind{
		name: name,
		merge: func(data [][]byte, strategy, format string, stdout, stderr io.Writer) int {
			return mergeProfiles(
				data, strategy, format, ops.intersect, ops.union, ops.format, stdout, stderr,
			)
		},
		diff: func(data [][]byte, format string, stdout, stderr io.Writer) int {
			return diffProfiles(data, format, ops.diff, ops.formatDiff, stdout, stderr)
		},
		validate: func(
			data [][]byte, mode validateMode, format string, stdout, stderr io.Writer,
		) int {
			check, ok := ops.checker(mode)
			if !ok {
				_, _ = fmt.Fprintf(
					stderr, "error: --artifact is not supported for %s profiles\n", name,
				)

				return exitUsage
			}

			return validateProfiles(
				data, check, mode == modeStrict, format, ops.format, stdout, stderr,
			)
		},
	}
}

// kindByName returns the profile kind registered under the given type name.
func kindByName(name string) (profileKind, bool) {
	switch name {
	case typeSeccomp:
		return newKind(name, kindOps[specs.LinuxSeccomp, seccomp.ProfileDiff]{
			intersect:        seccomp.Intersect,
			union:            seccomp.Union,
			validate:         seccomp.Validate,
			validateStrict:   seccomp.ValidateStrict,
			validateArtifact: seccomp.ValidateArtifact,
			format:           seccomp.FormatProfile,
			diff:             seccomp.Diff,
			formatDiff:       seccomp.FormatDiff,
		}), true
	case typeAppArmor:
		return newKind(name, kindOps[apparmor.Profile, apparmor.ProfileDiff]{
			intersect:        apparmor.Intersect,
			union:            apparmor.Union,
			validate:         apparmor.Validate,
			validateStrict:   apparmor.ValidateStrict,
			validateArtifact: nil,
			format:           apparmor.FormatProfile,
			diff:             apparmor.Diff,
			formatDiff:       apparmor.FormatDiff,
		}), true
	case typeLandlock:
		return newKind(name, kindOps[landlock.Profile, landlock.ProfileDiff]{
			intersect:        landlock.Intersect,
			union:            landlock.Union,
			validate:         landlock.Validate,
			validateStrict:   landlock.ValidateStrict,
			validateArtifact: nil,
			format:           landlock.FormatProfile,
			diff:             landlock.Diff,
			formatDiff:       landlock.FormatDiff,
		}), true
	default:
		var none profileKind

		return none, false
	}
}

// resolveKind returns the profile kind named by --type, or the one detected
// from the first input when the flag is empty.
func resolveKind(profileType string, data [][]byte, stderr io.Writer) (profileKind, int) {
	if profileType == "" {
		profileType = detectProfileType(data)
		if profileType == "" {
			_, _ = fmt.Fprintln(
				stderr, "error: could not detect profile type from input, use --type",
			)

			var none profileKind

			return none, exitUsage
		}

		_, _ = fmt.Fprintf(stderr, "auto-detected profile type: %s\n", profileType)
	}

	kind, ok := kindByName(profileType)
	if !ok {
		return kind, unknownType(stderr, profileType)
	}

	return kind, 0
}

// unknownType reports an unknown profile type and returns the usage exit
// code.
func unknownType(stderr io.Writer, name string) int {
	_, _ = fmt.Fprintf(
		stderr, "error: unknown type %q (use %s, %s, or %s)\n",
		name, typeSeccomp, typeAppArmor, typeLandlock,
	)

	return exitUsage
}
