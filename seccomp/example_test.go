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
	"fmt"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func ExampleIntersect() {
	baseline := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Intersect(baseline, profile)
	if err != nil {
		panic(err)
	}

	fmt.Println("Default:", result.DefaultAction)

	for _, sc := range result.Syscalls {
		fmt.Println("Syscall:", sc.Names[0], "->", sc.Action)
	}

	// Output:
	// Default: SCMP_ACT_ERRNO
	// Syscall: read -> SCMP_ACT_ALLOW
}

func ExampleValidate() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.LinuxSeccompAction("SCMP_ACT_BOGUS"),
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	fmt.Println(err)

	// Output:
	// default action: unknown seccomp action "SCMP_ACT_BOGUS"
}

func ExampleValidate_valid() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	err := seccomp.Validate(profile)
	fmt.Println(err)

	// Output:
	// <nil>
}

func ExampleMoreRestrictive() {
	result := seccomp.MoreRestrictive(specs.ActAllow, specs.ActErrno)
	fmt.Println(result)

	// Output:
	// SCMP_ACT_ERRNO
}

func ExampleLessRestrictive() {
	result := seccomp.LessRestrictive(specs.ActAllow, specs.ActErrno)
	fmt.Println(result)

	// Output:
	// SCMP_ACT_ALLOW
}

func ExampleUnionSyscalls() {
	result := seccomp.UnionSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	)

	for _, sc := range result {
		fmt.Printf("%s -> %s\n", strings.Join(sc.Names, ","), sc.Action)
	}

	// Output:
	// read,write -> SCMP_ACT_ALLOW
}

func ExampleIntersectSyscalls() {
	result := seccomp.IntersectSyscalls(
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
		[]specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActErrno},
		},
	)

	for _, sc := range result {
		fmt.Printf("%s -> %s\n", sc.Names[0], sc.Action)
	}

	// Output:
	// read -> SCMP_ACT_ERRNO
}

func ExampleFormatProfile() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	fmt.Println(seccomp.FormatProfile(profile))

	// Output:
	// Profile{default:SCMP_ACT_ERRNO read->SCMP_ACT_ALLOW write->SCMP_ACT_ALLOW}
}

func ExampleValidateStrict() {
	profile := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
			{Names: []string{syscallRead}, Action: specs.ActErrno},
		},
	}

	err := seccomp.ValidateStrict(profile)
	fmt.Println(err)

	// Output:
	// syscall "read" in entries 0 and 1: duplicate syscall name
}

func ExampleDiff() {
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallOpen}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("Equal:", diff.Equal)

	for _, r := range diff.Syscalls.Removed {
		fmt.Println("Removed:", r.Name)
	}

	for _, a := range diff.Syscalls.Added {
		fmt.Println("Added:", a.Name)
	}

	// Output:
	// Equal: false
	// Removed: write
	// Added: open
}

func ExampleFormatDiff() {
	left := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallWrite}, Action: specs.ActAllow},
		},
	}

	right := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead, syscallOpen}, Action: specs.ActAllow},
		},
	}

	diff, err := seccomp.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println(seccomp.FormatDiff(diff))

	// Output:
	// Diff{-write->SCMP_ACT_ALLOW +open->SCMP_ACT_ALLOW}
}

func ExampleUnion() {
	recording1 := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallRead}, Action: specs.ActAllow},
		},
	}

	recording2 := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Syscalls: []specs.LinuxSyscall{
			{Names: []string{syscallWrite}, Action: specs.ActAllow},
		},
	}

	result, err := seccomp.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("Default:", result.DefaultAction)

	for _, sc := range result.Syscalls {
		fmt.Println("Syscall:", strings.Join(sc.Names, ","), "->", sc.Action)
	}

	// Output:
	// Default: SCMP_ACT_ERRNO
	// Syscall: read,write -> SCMP_ACT_ALLOW
}
