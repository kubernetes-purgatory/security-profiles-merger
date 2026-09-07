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
	"math"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/seccomp"
)

// This file holds an independent evaluator for seccomp profiles and fuzz
// targets asserting the core safety properties of the merge operations:
//
//   - Intersect never permits a call that any input denies.
//   - Union never denies a call that any input permits.
//   - Both are idempotent and commutative in effect.
//
// The evaluator implements the model documented on seccomp.Intersect: among
// matching conditional entries the least restrictive action applies, else
// the unconditional entry, else the profile default.

var (
	safetyNames = []string{"read", "write", "clone", "socket"}

	safetyActions = []specs.LinuxSeccompAction{
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

	safetyOps = []specs.LinuxSeccompOperator{
		specs.OpNotEqual,
		specs.OpLessThan,
		specs.OpLessEqual,
		specs.OpEqualTo,
		specs.OpGreaterEqual,
		specs.OpGreaterThan,
		specs.OpMaskedEqual,
	}
)

// byteReader hands out bytes from fuzz data, yielding zero once exhausted.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) next() byte {
	if r.pos >= len(r.data) {
		return 0
	}

	val := r.data[r.pos]
	r.pos++

	return val
}

func (r *byteReader) exhausted() bool { return r.pos >= len(r.data) }

// safetyProfile decodes a profile from fuzz bytes. Entries may repeat
// syscall names, mix unconditional and conditional rules, and carry up to
// two argument filters on indices 0 and 1.
func safetyProfile(reader *byteReader) *specs.LinuxSeccomp {
	const (
		maxEntries = 6
		maxArgs    = 2
		valueSpan  = 8
	)

	profile := &specs.LinuxSeccomp{
		DefaultAction: safetyActions[int(reader.next())%len(safetyActions)],
	}

	if reader.next()%2 == 1 {
		errno := uint(reader.next())
		profile.DefaultErrnoRet = &errno
	}

	for range maxEntries {
		if reader.exhausted() {
			break
		}

		entry := specs.LinuxSyscall{
			Names:  []string{safetyNames[int(reader.next())%len(safetyNames)]},
			Action: safetyActions[int(reader.next())%len(safetyActions)],
		}

		if reader.next()%2 == 1 {
			errno := uint(reader.next())
			entry.ErrnoRet = &errno
		}

		argCount := int(reader.next()) % (maxArgs + 1)

		for argIdx := range argCount {
			arg := specs.LinuxSeccompArg{
				Index:    uint(argIdx),
				Value:    uint64(reader.next() % valueSpan),
				ValueTwo: uint64(reader.next() % valueSpan),
				Op:       safetyOps[int(reader.next())%len(safetyOps)],
			}
			entry.Args = append(entry.Args, arg)
		}

		profile.Syscalls = append(profile.Syscalls, entry)
	}

	return profile
}

func entryMatches(entry specs.LinuxSyscall, call []uint64) bool {
	for _, arg := range entry.Args {
		if int(arg.Index) >= len(call) || !seccomp.CondHolds(arg, call[arg.Index]) {
			return false
		}
	}

	return true
}

// evalCall returns the action a profile applies to a call of the named
// syscall with the given argument values.
func evalCall(
	profile *specs.LinuxSeccomp, name string, call []uint64,
) specs.LinuxSeccompAction {
	var (
		conditional   specs.LinuxSeccompAction
		unconditional specs.LinuxSeccompAction
		hasCond       bool
		hasUncond     bool
	)

	for _, entry := range profile.Syscalls {
		if !slices.Contains(entry.Names, name) {
			continue
		}

		if len(entry.Args) == 0 {
			if !hasUncond {
				unconditional = entry.Action
				hasUncond = true
			} else {
				unconditional = seccomp.LessRestrictive(unconditional, entry.Action)
			}

			continue
		}

		if !entryMatches(entry, call) {
			continue
		}

		if !hasCond {
			conditional = entry.Action
			hasCond = true
		} else {
			conditional = seccomp.LessRestrictive(conditional, entry.Action)
		}
	}

	switch {
	case hasCond:
		return conditional
	case hasUncond:
		return unconditional
	default:
		return profile.DefaultAction
	}
}

// atMostAsPermissive reports whether first is at most as permissive as
// second.
func atMostAsPermissive(first, second specs.LinuxSeccompAction) bool {
	return seccomp.MoreRestrictive(first, second) == first
}

// sampleValues collects boundary values around every filter value in the
// profiles so each argument condition is exercised on both sides.
func sampleValues(profiles ...*specs.LinuxSeccomp) []uint64 {
	values := []uint64{0, 1, math.MaxUint64}

	for _, profile := range profiles {
		for _, entry := range profile.Syscalls {
			for _, arg := range entry.Args {
				for _, base := range []uint64{arg.Value, arg.ValueTwo} {
					values = append(values, base, base+1)

					if base > 0 {
						values = append(values, base-1)
					}
				}
			}
		}
	}

	slices.Sort(values)

	return slices.Compact(values)
}

// forEachCall invokes fn for every syscall name and sampled argument vector.
func forEachCall(
	profiles []*specs.LinuxSeccomp,
	visit func(name string, call []uint64),
) {
	values := sampleValues(profiles...)

	for _, name := range safetyNames {
		for _, first := range values {
			for _, second := range values {
				visit(name, []uint64{first, second})
			}
		}
	}
}

func safetyInputs(t *testing.T, data []byte) (*specs.LinuxSeccomp, *specs.LinuxSeccomp) {
	t.Helper()

	reader := &byteReader{data: data, pos: 0}
	left := safetyProfile(reader)
	right := safetyProfile(reader)

	err := seccomp.Validate(left)
	if err != nil {
		t.Skip("invalid left input")
	}

	err = seccomp.Validate(right)
	if err != nil {
		t.Skip("invalid right input")
	}

	return left, right
}

func addSafetySeeds(f *testing.F) {
	f.Helper()

	// Baseline with two conditional entries for the same syscall versus an
	// unconditional allow.
	f.Add([]byte{
		4, 0, 2, 8, 0, 1, 0, 0, 3, 2, 8, 0, 1, 1, 0, 3,
		4, 0, 2, 8, 0, 0,
	})
	// Unconditional deny on one side, conditional allow on the other.
	f.Add([]byte{
		8, 0, 3, 4, 0, 0,
		8, 0, 3, 8, 0, 1, 2, 0, 3,
	})
	// Same profile shape twice, with an unconditional and a conditional
	// entry for the same syscall.
	f.Add([]byte{
		8, 0, 3, 4, 0, 0, 3, 8, 0, 1, 2, 0, 3,
		8, 0, 3, 4, 0, 0, 3, 8, 0, 1, 2, 0, 3,
	})
	// Overlapping ranges on the same index.
	f.Add([]byte{
		4, 0, 2, 8, 0, 1, 1, 0, 4,
		4, 0, 2, 8, 0, 1, 5, 0, 2,
	})
	// Errno values everywhere.
	f.Add([]byte{
		4, 1, 13, 0, 4, 1, 42, 1, 3, 0, 3,
		4, 1, 99, 0, 4, 1, 7, 0,
	})
}

func FuzzIntersectSafety(f *testing.F) {
	addSafetySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		left, right := safetyInputs(t, data)

		result, err := seccomp.Intersect(left, right)
		if err != nil {
			t.Fatalf("intersect: %v", err)
		}

		err = seccomp.Validate(result)
		if err != nil {
			t.Fatalf("result fails validation: %v", err)
		}

		reversed, err := seccomp.Intersect(right, left)
		if err != nil {
			t.Fatalf("reversed intersect: %v", err)
		}

		self, err := seccomp.Intersect(left, left)
		if err != nil {
			t.Fatalf("self intersect: %v", err)
		}

		forEachCall([]*specs.LinuxSeccomp{left, right}, func(name string, call []uint64) {
			got := evalCall(result, name, call)
			leftAction := evalCall(left, name, call)
			rightAction := evalCall(right, name, call)

			if !atMostAsPermissive(got, leftAction) || !atMostAsPermissive(got, rightAction) {
				t.Errorf(
					"%s%v: intersect yields %s, inputs yield %s and %s\n  left:   %s\n  right:  %s\n  result: %s",
					name,
					call,
					got,
					leftAction,
					rightAction,
					seccomp.FormatProfile(left),
					seccomp.FormatProfile(right),
					seccomp.FormatProfile(result),
				)
			}

			if !sameRestrictiveness(got, evalCall(reversed, name, call)) {
				t.Errorf("%s%v: intersect is not commutative", name, call)
			}

			if !sameRestrictiveness(evalCall(self, name, call), leftAction) {
				t.Errorf(
					"%s%v: Intersect(X,X) yields %s, X yields %s\n  input:  %s\n  result: %s",
					name, call, evalCall(self, name, call), leftAction,
					seccomp.FormatProfile(left),
					seccomp.FormatProfile(self),
				)
			}
		})
	})
}

func FuzzUnionSafety(f *testing.F) {
	addSafetySeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		left, right := safetyInputs(t, data)

		result, err := seccomp.Union(left, right)
		if err != nil {
			t.Fatalf("union: %v", err)
		}

		err = seccomp.Validate(result)
		if err != nil {
			t.Fatalf("result fails validation: %v", err)
		}

		reversed, err := seccomp.Union(right, left)
		if err != nil {
			t.Fatalf("reversed union: %v", err)
		}

		self, err := seccomp.Union(left, left)
		if err != nil {
			t.Fatalf("self union: %v", err)
		}

		forEachCall([]*specs.LinuxSeccomp{left, right}, func(name string, call []uint64) {
			got := evalCall(result, name, call)
			leftAction := evalCall(left, name, call)
			rightAction := evalCall(right, name, call)

			if !atMostAsPermissive(leftAction, got) || !atMostAsPermissive(rightAction, got) {
				t.Errorf(
					"%s%v: union yields %s, inputs yield %s and %s\n  left:   %s\n  right:  %s\n  result: %s",
					name,
					call,
					got,
					leftAction,
					rightAction,
					seccomp.FormatProfile(left),
					seccomp.FormatProfile(right),
					seccomp.FormatProfile(result),
				)
			}

			if !sameRestrictiveness(got, evalCall(reversed, name, call)) {
				t.Errorf("%s%v: union is not commutative", name, call)
			}

			if !sameRestrictiveness(evalCall(self, name, call), leftAction) {
				t.Errorf(
					"%s%v: Union(X,X) yields %s, X yields %s\n  input:  %s\n  result: %s",
					name, call, evalCall(self, name, call), leftAction,
					seccomp.FormatProfile(left),
					seccomp.FormatProfile(self),
				)
			}
		})
	})
}
