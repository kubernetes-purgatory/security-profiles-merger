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

package seccomp_test

import (
	"errors"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := seccomp.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	err := seccomp.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownDefaultAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown default action")
	}
}

func TestValidateUnknownSyscallAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: "SCMP_ACT_BOGUS"},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown syscall action")
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: "SCMP_ACT_BOGUS"},
			{Names: []string{syscallWrite}, Action: "SCMP_ACT_FAKE"},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for multiple invalid actions")
	}

	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Errorf("expected ErrUnknownAction, got: %v", err)
	}

	msg := err.Error()
	if !strings.Contains(msg, "default action") {
		t.Errorf("error should mention default action: %v", err)
	}

	if !strings.Contains(msg, "syscall entry 0") {
		t.Errorf("error should mention syscall entry 0: %v", err)
	}

	if !strings.Contains(msg, "syscall entry 1") {
		t.Errorf("error should mention syscall entry 1: %v", err)
	}
}

func TestValidateEmptySyscallNames(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: nil, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty syscall names")
	}

	if !errors.Is(err, seccomp.ErrEmptySyscallNames) {
		t.Errorf("expected ErrEmptySyscallNames, got: %v", err)
	}
}

func TestValidateEmptySyscallName(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, ""}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty syscall name in list")
	}

	if !errors.Is(err, seccomp.ErrEmptySyscallName) {
		t.Errorf("expected ErrEmptySyscallName, got: %v", err)
	}
}

func TestValidateAllKnownActions(t *testing.T) {
	t.Parallel()

	actions := []specs.LinuxSeccompAction{
		specs.ActKillProcess,
		specs.ActKillThread,
		specs.ActKill,
		specs.ActTrap,
		specs.ActErrno,
		specs.ActTrace,
		specs.ActNotify,
		specs.ActLog,
		specs.ActAllow,
	}

	for _, action := range actions {
		profile := &specs.LinuxSeccomp{DefaultAction: action}

		err := seccomp.Validate(profile)
		if err != nil {
			t.Errorf("unexpected error for action %q: %v", action, err)
		}
	}
}

func TestValidateStrictNil(t *testing.T) {
	t.Parallel()

	err := seccomp.ValidateStrict(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}

	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateStrictDuplicateSyscallName(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActLog},
		},
	}

	err := seccomp.Validate(profile)
	if err != nil {
		t.Fatalf("Validate should permit duplicate names: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate syscall name")
	}

	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Errorf("expected ErrDuplicateSyscallName, got: %v", err)
	}
}

func TestValidateStrictNoDuplicates(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActLog},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActLog},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	if !errors.Is(err, seccomp.ErrUnknownAction) {
		t.Errorf("expected ErrUnknownAction, got: %v", err)
	}

	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Error("expected ErrDuplicateSyscallName alongside Validate errors")
	}
}

func TestValidateStrictCollectsAllNewErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 6, Value: 1, Op: "SCMP_CMP_BOGUS"},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	for _, sentinel := range []error{
		seccomp.ErrUnknownArch,
		seccomp.ErrUnknownFlag,
		seccomp.ErrUnknownOperator,
		seccomp.ErrArgIndexOutOfRange,
	} {
		if !errors.Is(err, sentinel) {
			t.Errorf("expected %v in error, got: %v", sentinel, err)
		}
	}
}

func TestValidateStrictUnknownArch(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unknown architecture")
	}

	if !errors.Is(err, seccomp.ErrUnknownArch) {
		t.Errorf("expected ErrUnknownArch, got: %v", err)
	}
}

func TestValidateStrictAllKnownArchs(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{
			specs.ArchX86, specs.ArchX86_64, specs.ArchX32,
			specs.ArchARM, specs.ArchAARCH64,
			specs.ArchMIPS, specs.ArchMIPS64, specs.ArchMIPS64N32,
			specs.ArchMIPSEL, specs.ArchMIPSEL64, specs.ArchMIPSEL64N32,
			specs.ArchPPC, specs.ArchPPC64, specs.ArchPPC64LE,
			specs.ArchS390, specs.ArchS390X,
			specs.ArchPARISC, specs.ArchPARISC64,
			specs.ArchRISCV64, specs.ArchLOONGARCH64,
			specs.ArchM68K, specs.ArchSH, specs.ArchSHEB,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictUnknownFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unknown flag")
	}

	if !errors.Is(err, seccomp.ErrUnknownFlag) {
		t.Errorf("expected ErrUnknownFlag, got: %v", err)
	}
}

func TestValidateStrictAllKnownFlags(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
			specs.LinuxSeccompFlagWaitKillableRecv,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictDuplicateArch(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{
			specs.ArchX86_64, specs.ArchARM, specs.ArchX86_64,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate architecture")
	}

	if !errors.Is(err, seccomp.ErrDuplicateArch) {
		t.Errorf("expected ErrDuplicateArch, got: %v", err)
	}

	if strings.Count(err.Error(), "duplicate architecture") != 1 {
		t.Errorf("expected exactly one duplicate report, got: %v", err)
	}
}

func TestValidateStrictDuplicateFlag(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Flags: []specs.LinuxSeccompFlag{
			specs.LinuxSeccompFlagLog,
			specs.LinuxSeccompFlagSpecAllow,
			specs.LinuxSeccompFlagLog,
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for duplicate flag")
	}

	if !errors.Is(err, seccomp.ErrDuplicateFlag) {
		t.Errorf("expected ErrDuplicateFlag, got: %v", err)
	}

	if strings.Count(err.Error(), "duplicate seccomp flag") != 1 {
		t.Errorf("expected exactly one duplicate report, got: %v", err)
	}
}

func TestValidateStrictUnknownArgOperator(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: "SCMP_CMP_BOGUS"},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unknown operator")
	}

	if !errors.Is(err, seccomp.ErrUnknownOperator) {
		t.Errorf("expected ErrUnknownOperator, got: %v", err)
	}
}

func TestValidateStrictArgIndexOutOfRange(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 6, Value: 1, Op: specs.OpEqualTo},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for arg index out of range")
	}

	if !errors.Is(err, seccomp.ErrArgIndexOutOfRange) {
		t.Errorf("expected ErrArgIndexOutOfRange, got: %v", err)
	}
}

func TestValidateStrictValidArgs(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
					{Index: 5, Value: 2, Op: specs.OpMaskedEqual},
				},
			},
		},
	}

	err := seccomp.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictAllKnownOperators(t *testing.T) {
	t.Parallel()

	operators := []specs.LinuxSeccompOperator{
		specs.OpNotEqual, specs.OpLessThan, specs.OpLessEqual,
		specs.OpEqualTo, specs.OpGreaterEqual, specs.OpGreaterThan,
		specs.OpMaskedEqual,
	}

	for _, operator := range operators {
		t.Run(string(operator), func(t *testing.T) {
			t.Parallel()

			profile := &specs.LinuxSeccomp{
				DefaultAction: specs.ActErrno,
				Syscalls: []specs.LinuxSyscall{
					{
						Names:  []string{syscallRead},
						Action: specs.ActAllow,
						Args: []specs.LinuxSeccompArg{
							{Index: 0, Value: 1, Op: operator},
						},
					},
				},
			}

			err := seccomp.ValidateStrict(profile)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateArtifactNil(t *testing.T) {
	t.Parallel()

	err := seccomp.ValidateArtifact(nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Fatalf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateArtifactValid(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchX86_64, specs.ArchX86},
		Flags:         []specs.LinuxSeccompFlag{specs.LinuxSeccompFlagLog},
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActTrace},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateArtifactAllowsDuplicateSyscallNames(t *testing.T) {
	t.Parallel()

	// The OCI runtime-spec allows one syscall in several entries with
	// different argument filters, so artifacts may use that shape.
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallWrite},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 1, Op: specs.OpEqualTo},
				},
			},
			{
				Names:  []string{syscallWrite},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 0, Value: 2, Op: specs.OpEqualTo},
				},
			},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Fatalf("expected ValidateStrict to reject duplicates, got: %v", err)
	}
}

func TestValidateArtifactRejectsNotifyDefaultAction(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActNotify,
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrNotifyNotAllowed) {
		t.Fatalf("expected ErrNotifyNotAllowed, got: %v", err)
	}

	if !strings.Contains(err.Error(), "default action") {
		t.Errorf("error should mention default action: %v", err)
	}

	err = seccomp.ValidateStrict(profile)
	if err != nil {
		t.Errorf("ValidateStrict should accept SCMP_ACT_NOTIFY: %v", err)
	}
}

func TestValidateArtifactRejectsNotifySyscall(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActNotify},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrNotifyNotAllowed) {
		t.Fatalf("expected ErrNotifyNotAllowed, got: %v", err)
	}

	if !strings.Contains(err.Error(), "syscall entry 1") {
		t.Errorf("error should mention syscall entry 1: %v", err)
	}
}

func TestValidateArtifactRejectsListener(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction:    specs.ActErrno,
		ListenerPath:     "/run/seccomp-agent.sock",
		ListenerMetadata: "opaque",
	}

	err := seccomp.ValidateArtifact(profile)
	if !errors.Is(err, seccomp.ErrListenerNotAllowed) {
		t.Fatalf("expected ErrListenerNotAllowed, got: %v", err)
	}

	msg := err.Error()
	for _, field := range []string{"listenerPath", "listenerMetadata"} {
		if !strings.Contains(msg, field) {
			t.Errorf("error should mention %s: %v", field, err)
		}
	}

	err = seccomp.ValidateStrict(profile)
	if err != nil {
		t.Errorf("ValidateStrict should accept listener settings: %v", err)
	}
}

func TestValidateArtifactRunsShapeChecks(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{"SCMP_ARCH_BOGUS"},
		Flags:         []specs.LinuxSeccompFlag{"SECCOMP_FILTER_FLAG_BOGUS"},
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  []string{syscallRead},
				Action: specs.ActAllow,
				Args: []specs.LinuxSeccompArg{
					{Index: 7, Value: 0, Op: "SCMP_CMP_BOGUS"},
				},
			},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err == nil {
		t.Fatal("expected error for invalid profile shape")
	}

	for _, want := range []error{
		seccomp.ErrUnknownArch,
		seccomp.ErrUnknownFlag,
		seccomp.ErrUnknownOperator,
		seccomp.ErrArgIndexOutOfRange,
	} {
		if !errors.Is(err, want) {
			t.Errorf("expected %v in: %v", want, err)
		}
	}
}

func TestValidateArtifactCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &specs.LinuxSeccomp{
		DefaultAction: actInvalid,
		ListenerPath:  "/run/seccomp-agent.sock",
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActNotify},
		},
	}

	err := seccomp.ValidateArtifact(profile)
	if err == nil {
		t.Fatal("expected error")
	}

	for _, want := range []error{
		seccomp.ErrUnknownAction,
		seccomp.ErrNotifyNotAllowed,
		seccomp.ErrListenerNotAllowed,
	} {
		if !errors.Is(err, want) {
			t.Errorf("expected %v in: %v", want, err)
		}
	}
}

func TestValidateArtifactEntryCount(t *testing.T) {
	t.Parallel()

	entries := make([]specs.LinuxSyscall, 0, seccomp.MaxArtifactEntriesPerSyscall+1)
	for idx := range seccomp.MaxArtifactEntriesPerSyscall + 1 {
		entries = append(entries, specs.LinuxSyscall{
			Names:  []string{syscallWrite},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: uint64(idx), Op: specs.OpEqualTo},
			},
		})
	}

	over := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno, Syscalls: entries}

	err := seccomp.ValidateArtifact(over)
	if !errors.Is(err, seccomp.ErrTooManyEntries) {
		t.Fatalf("expected ErrTooManyEntries, got: %v", err)
	}

	if !strings.Contains(err.Error(), syscallWrite) {
		t.Errorf("error should name the syscall: %v", err)
	}

	err = seccomp.ValidateStrict(over)
	if !errors.Is(err, seccomp.ErrDuplicateSyscallName) {
		t.Errorf("ValidateStrict should only report duplicates: %v", err)
	}

	atLimit := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls:      entries[:seccomp.MaxArtifactEntriesPerSyscall],
	}

	err = seccomp.ValidateArtifact(atLimit)
	if err != nil {
		t.Fatalf("profile at the limit should validate: %v", err)
	}
}
