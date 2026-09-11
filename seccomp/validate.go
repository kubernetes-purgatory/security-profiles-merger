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

package seccomp

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const maxSyscallArgIndex = 5

var (
	// ErrUnknownAction is returned when a profile contains an unrecognized
	// seccomp action.
	ErrUnknownAction = errors.New("unknown seccomp action")
	// ErrEmptySyscallNames is returned when a syscall entry has no names.
	ErrEmptySyscallNames = errors.New("syscall entry has no names")
	// ErrEmptySyscallName is returned when a syscall entry contains an
	// empty string in its name list.
	ErrEmptySyscallName = errors.New("empty syscall name")
	// ErrDuplicateSyscallName is returned when the same syscall name
	// appears in more than one syscall entry.
	ErrDuplicateSyscallName = errors.New("duplicate syscall name")
	// ErrUnknownOperator is returned when a syscall arg contains an
	// unrecognized comparison operator.
	ErrUnknownOperator = errors.New("unknown seccomp operator")
	// ErrArgIndexOutOfRange is returned when a syscall arg index exceeds
	// the maximum (5).
	ErrArgIndexOutOfRange = errors.New("syscall arg index out of range")
	// ErrUnknownArch is returned when a profile contains an unrecognized
	// architecture.
	ErrUnknownArch = errors.New("unknown architecture")
	// ErrDuplicateArch is returned when the same architecture appears
	// more than once.
	ErrDuplicateArch = errors.New("duplicate architecture")
	// ErrUnknownFlag is returned when a profile contains an unrecognized
	// seccomp flag.
	ErrUnknownFlag = errors.New("unknown seccomp flag")
	// ErrDuplicateFlag is returned when the same flag appears more than
	// once.
	ErrDuplicateFlag = errors.New("duplicate seccomp flag")
	// ErrNotifyNotAllowed is returned by ValidateArtifact when a profile
	// uses SCMP_ACT_NOTIFY, which needs a listener that an artifact cannot
	// provide.
	ErrNotifyNotAllowed = errors.New("SCMP_ACT_NOTIFY is not allowed")
	// ErrListenerNotAllowed is returned by ValidateArtifact when a profile
	// sets listenerPath or listenerMetadata, which name node-local
	// resources that an artifact must not control.
	ErrListenerNotAllowed = errors.New("listener settings are not allowed")
	// ErrTooManyEntries is returned by ValidateArtifact when one syscall
	// name appears in more than MaxArtifactEntriesPerSyscall entries.
	ErrTooManyEntries = errors.New("too many entries for syscall")
)

// MaxArtifactEntriesPerSyscall bounds how many entries may name the same
// syscall in a profile accepted by ValidateArtifact. Intersect compares
// every entry for a syscall against every entry for the same syscall in the
// other profile, so the cost per syscall grows quadratically with the entry
// count. Real profiles use a handful of argument-filtered entries per
// syscall; the cap keeps a 1 MiB artifact from turning the merge into a
// multi-second operation.
const MaxArtifactEntriesPerSyscall = 128

// Validate checks that a seccomp profile contains only known actions and
// that every syscall entry has non-empty names. Intersect and Union run it
// on every input and fail on the first invalid profile, so callers that
// want to report all problems up front can call it themselves. All
// validation failures are collected and returned together.
func Validate(profile *specs.LinuxSeccomp) error {
	if profile == nil {
		return ErrNilProfile
	}

	var errs []error

	err := validateAction(profile.DefaultAction, "default action")
	if err != nil {
		errs = append(errs, err)
	}

	for idx := range profile.Syscalls {
		if len(profile.Syscalls[idx].Names) == 0 {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d: %w", idx, ErrEmptySyscallNames,
			))
		}

		if slices.Contains(profile.Syscalls[idx].Names, "") {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d: %w", idx, ErrEmptySyscallName,
			))
		}

		err := validateAction(
			profile.Syscalls[idx].Action,
			fmt.Sprintf("syscall entry %d action", idx),
		)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// ValidateStrict performs all checks from Validate and additionally detects
// duplicate syscall names across entries, unknown architectures, unknown
// flags, unknown arg operators, and out-of-range arg indices. The OCI
// runtime-spec allows the same syscall to appear in multiple entries (for
// example with different argument filters), so the merge path uses Validate
// which permits this. ValidateStrict is intended for user-authored profiles
// where duplicates are likely mistakes.
func ValidateStrict(profile *specs.LinuxSeccomp) error {
	return validateWith(profile, validateDuplicateNames, validateShape)
}

// ValidateArtifact validates a profile received from an untrusted source,
// such as an OCI artifact pulled by a container runtime (KEP-6061). It
// performs all checks from Validate and the shape checks from ValidateStrict
// (unknown or duplicate architectures and flags, unknown arg operators, and
// out-of-range arg indices), and rejects two things a distributed profile
// must not control: SCMP_ACT_NOTIFY, because it needs a listener that only
// the runtime can provide, and listenerPath or listenerMetadata, because they
// name a node-local socket. Duplicate syscall names are allowed, as the OCI
// runtime-spec permits them and Intersect handles them, but no syscall may
// appear in more than MaxArtifactEntriesPerSyscall entries, which bounds the
// merge cost. ValidateArtifact does not compare the profile against a
// baseline; callers intersect the result with their baseline afterwards.
func ValidateArtifact(profile *specs.LinuxSeccomp) error {
	return validateWith(
		profile,
		validateShape,
		validateNoNotify,
		validateNoListener,
		validateEntryCount,
	)
}

type profileCheck func(profile *specs.LinuxSeccomp) error

// validateWith runs Validate and, if the profile is non-nil, every check,
// collecting all failures into one error.
func validateWith(profile *specs.LinuxSeccomp, checks ...profileCheck) error {
	errs := []error{Validate(profile)}

	if profile == nil {
		return errors.Join(errs...)
	}

	for _, check := range checks {
		errs = append(errs, check(profile))
	}

	return errors.Join(errs...)
}

// validateShape runs the checks shared by ValidateStrict and
// ValidateArtifact that do not depend on trust: unknown or duplicate
// architectures and flags, unknown arg operators, and out-of-range arg
// indices.
func validateShape(profile *specs.LinuxSeccomp) error {
	return errors.Join(
		validateArchitectures(profile.Architectures),
		validateDuplicateArchitectures(profile.Architectures),
		validateFlags(profile.Flags),
		validateDuplicateFlags(profile.Flags),
		validateSyscallArgs(profile.Syscalls),
	)
}

func validateDuplicateNames(profile *specs.LinuxSeccomp) error {
	return validateDuplicateSyscallNames(profile.Syscalls)
}

func validateNoNotify(profile *specs.LinuxSeccomp) error {
	var errs []error

	if profile.DefaultAction == specs.ActNotify {
		errs = append(errs, fmt.Errorf(
			"default action: %w", ErrNotifyNotAllowed,
		))
	}

	for idx := range profile.Syscalls {
		if profile.Syscalls[idx].Action == specs.ActNotify {
			errs = append(errs, fmt.Errorf(
				"syscall entry %d action: %w", idx, ErrNotifyNotAllowed,
			))
		}
	}

	return errors.Join(errs...)
}

func validateEntryCount(profile *specs.LinuxSeccomp) error {
	counts := make(map[string]int)

	for idx := range profile.Syscalls {
		for _, name := range profile.Syscalls[idx].Names {
			counts[name]++
		}
	}

	var errs []error

	for _, name := range slices.Sorted(maps.Keys(counts)) {
		if counts[name] > MaxArtifactEntriesPerSyscall {
			errs = append(errs, fmt.Errorf(
				"syscall %q: %w (%d, max %d)",
				name, ErrTooManyEntries, counts[name],
				MaxArtifactEntriesPerSyscall,
			))
		}
	}

	return errors.Join(errs...)
}

func validateNoListener(profile *specs.LinuxSeccomp) error {
	var errs []error

	if profile.ListenerPath != "" {
		errs = append(errs, fmt.Errorf(
			"listenerPath: %w", ErrListenerNotAllowed,
		))
	}

	if profile.ListenerMetadata != "" {
		errs = append(errs, fmt.Errorf(
			"listenerMetadata: %w", ErrListenerNotAllowed,
		))
	}

	return errors.Join(errs...)
}

func validateDuplicateSyscallNames(syscalls []specs.LinuxSyscall) error {
	seen := make(map[string]int)

	var errs []error

	for idx, sc := range syscalls {
		for _, name := range sc.Names {
			if prev, ok := seen[name]; ok {
				errs = append(errs, fmt.Errorf(
					"syscall %q in entries %d and %d: %w",
					name, prev, idx, ErrDuplicateSyscallName,
				))
			} else {
				seen[name] = idx
			}
		}
	}

	return errors.Join(errs...)
}

func validateAction(action specs.LinuxSeccompAction, context string) error {
	if restrictiveness(action) == levelUnknown {
		return fmt.Errorf("%s: %w %q", context, ErrUnknownAction, action)
	}

	return nil
}

func isKnownOperator(op specs.LinuxSeccompOperator) bool {
	switch op {
	case specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
		specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		specs.OpMaskedEqual:
		return true
	default:
		return false
	}
}

func isKnownArch(arch specs.Arch) bool {
	switch arch {
	case specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
		specs.ArchARM, specs.ArchAARCH64,
		specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
		specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
		specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
		specs.ArchS390, specs.ArchS390X,
		specs.ArchPARISC, specs.ArchPARISC64,
		specs.ArchRISCV64, specs.ArchLOONGARCH64,
		specs.ArchM68K, specs.ArchSH, specs.ArchSHEB:
		return true
	default:
		return false
	}
}

func isKnownFlag(flag specs.LinuxSeccompFlag) bool {
	switch flag {
	case specs.LinuxSeccompFlagLog,
		specs.LinuxSeccompFlagSpecAllow,
		specs.LinuxSeccompFlagWaitKillableRecv:
		return true
	default:
		return false
	}
}

func validateArchitectures(archs []specs.Arch) error {
	var errs []error

	for _, arch := range archs {
		if !isKnownArch(arch) {
			errs = append(errs, fmt.Errorf(
				"architecture: %w %q", ErrUnknownArch, arch,
			))
		}
	}

	return errors.Join(errs...)
}

func validateFlags(flags []specs.LinuxSeccompFlag) error {
	var errs []error

	for _, flag := range flags {
		if !isKnownFlag(flag) {
			errs = append(errs, fmt.Errorf(
				"flag: %w %q", ErrUnknownFlag, flag,
			))
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateArchitectures(archs []specs.Arch) error {
	seen := make(map[specs.Arch]struct{}, len(archs))

	var errs []error

	for _, arch := range archs {
		if _, ok := seen[arch]; ok {
			errs = append(errs, fmt.Errorf(
				"architecture: %w %q", ErrDuplicateArch, arch,
			))
		} else {
			seen[arch] = struct{}{}
		}
	}

	return errors.Join(errs...)
}

func validateDuplicateFlags(flags []specs.LinuxSeccompFlag) error {
	seen := make(map[specs.LinuxSeccompFlag]struct{}, len(flags))

	var errs []error

	for _, flag := range flags {
		if _, ok := seen[flag]; ok {
			errs = append(errs, fmt.Errorf(
				"flag: %w %q", ErrDuplicateFlag, flag,
			))
		} else {
			seen[flag] = struct{}{}
		}
	}

	return errors.Join(errs...)
}

func validateSyscallArgs(syscalls []specs.LinuxSyscall) error {
	var errs []error

	for idx, sc := range syscalls {
		for argIdx, arg := range sc.Args {
			if !isKnownOperator(arg.Op) {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w %q",
					idx, argIdx, ErrUnknownOperator, arg.Op,
				))
			}

			if arg.Index > maxSyscallArgIndex {
				errs = append(errs, fmt.Errorf(
					"syscall entry %d arg %d: %w %d",
					idx, argIdx, ErrArgIndexOutOfRange, arg.Index,
				))
			}
		}
	}

	return errors.Join(errs...)
}
