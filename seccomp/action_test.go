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
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestMoreRestrictive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b specs.LinuxSeccompAction
		want specs.LinuxSeccompAction
	}{
		{"kill vs allow", specs.ActKillProcess, specs.ActAllow, specs.ActKillProcess},
		{"allow vs kill", specs.ActAllow, specs.ActKillProcess, specs.ActKillProcess},
		{"errno vs allow", specs.ActErrno, specs.ActAllow, specs.ActErrno},
		{"trap vs errno", specs.ActTrap, specs.ActErrno, specs.ActTrap},
		{"notify vs trace", specs.ActNotify, specs.ActTrace, specs.ActNotify},
		{"log vs allow", specs.ActLog, specs.ActAllow, specs.ActLog},
		{"same action", specs.ActErrno, specs.ActErrno, specs.ActErrno},
		{
			"kill process > kill thread",
			specs.ActKillThread,
			specs.ActKillProcess,
			specs.ActKillProcess,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := seccomp.MoreRestrictive(testCase.a, testCase.b)
			if got != testCase.want {
				t.Errorf(
					"MoreRestrictive(%q, %q) = %q, want %q",
					testCase.a, testCase.b, got, testCase.want,
				)
			}
		})
	}
}

func TestLessRestrictive(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b specs.LinuxSeccompAction
		want specs.LinuxSeccompAction
	}{
		{"kill vs allow", specs.ActKillProcess, specs.ActAllow, specs.ActAllow},
		{"errno vs allow", specs.ActErrno, specs.ActAllow, specs.ActAllow},
		{"trap vs errno", specs.ActTrap, specs.ActErrno, specs.ActErrno},
		{"same action", specs.ActAllow, specs.ActAllow, specs.ActAllow},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := seccomp.LessRestrictive(testCase.a, testCase.b)
			if got != testCase.want {
				t.Errorf(
					"LessRestrictive(%q, %q) = %q, want %q",
					testCase.a, testCase.b, got, testCase.want,
				)
			}
		})
	}
}

func TestActKillAndActKillThreadEquivalent(t *testing.T) {
	t.Parallel()

	got := seccomp.MoreRestrictive(specs.ActKill, specs.ActKillThread)
	if got != specs.ActKill {
		t.Errorf("MoreRestrictive(ActKill, ActKillThread) = %q, want %q", got, specs.ActKill)
	}

	got = seccomp.MoreRestrictive(specs.ActKillThread, specs.ActKill)
	if got != specs.ActKillThread {
		t.Errorf("MoreRestrictive(ActKillThread, ActKill) = %q, want %q", got, specs.ActKillThread)
	}

	got = seccomp.LessRestrictive(specs.ActKill, specs.ActKillThread)
	if got != specs.ActKill {
		t.Errorf("LessRestrictive(ActKill, ActKillThread) = %q, want %q", got, specs.ActKill)
	}
}

func TestUnknownActionIsMostRestrictive(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompAction("SCMP_ACT_UNKNOWN")

	got := seccomp.MoreRestrictive(unknown, specs.ActAllow)
	if got != unknown {
		t.Errorf("MoreRestrictive(unknown, allow) = %q, want %q", got, unknown)
	}

	got = seccomp.MoreRestrictive(specs.ActKillProcess, unknown)
	if got != unknown {
		t.Errorf("MoreRestrictive(kill, unknown) = %q, want %q", got, unknown)
	}
}

func TestLessRestrictiveUnknownAction(t *testing.T) {
	t.Parallel()

	unknown := specs.LinuxSeccompAction("SCMP_ACT_UNKNOWN")

	got := seccomp.LessRestrictive(unknown, specs.ActAllow)
	if got != specs.ActAllow {
		t.Errorf("LessRestrictive(unknown, allow) = %q, want %q", got, specs.ActAllow)
	}

	got = seccomp.LessRestrictive(specs.ActAllow, unknown)
	if got != specs.ActAllow {
		t.Errorf("LessRestrictive(allow, unknown) = %q, want %q", got, specs.ActAllow)
	}

	got = seccomp.LessRestrictive(unknown, unknown)
	if got != unknown {
		t.Errorf("LessRestrictive(unknown, unknown) = %q, want %q", got, unknown)
	}
}
