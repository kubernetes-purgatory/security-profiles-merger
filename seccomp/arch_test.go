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
	"runtime"
	"slices"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"sigs.k8s.io/security-profiles-merger/seccomp"
)

func TestNativeArchitecture(t *testing.T) {
	t.Parallel()

	arch, known := seccomp.NativeArchitecture()

	switch runtime.GOARCH {
	case "amd64":
		if !known || arch != specs.ArchX86_64 {
			t.Errorf("native = %q, %v; want %q", arch, known, specs.ArchX86_64)
		}
	case "arm64":
		if !known || arch != specs.ArchAARCH64 {
			t.Errorf("native = %q, %v; want %q", arch, known, specs.ArchAARCH64)
		}
	default:
		if known && arch == "" {
			t.Error("known native architecture must not be empty")
		}
	}
}

func TestPopulateNativeArchitecture(t *testing.T) {
	t.Parallel()

	err := seccomp.PopulateNativeArchitecture(nil)
	if !errors.Is(err, seccomp.ErrNilProfile) {
		t.Errorf("nil profile: expected ErrNilProfile, got %v", err)
	}

	preset := &specs.LinuxSeccomp{
		DefaultAction: specs.ActErrno,
		Architectures: []specs.Arch{specs.ArchARM},
	}

	err = seccomp.PopulateNativeArchitecture(preset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(preset.Architectures, []specs.Arch{specs.ArchARM}) {
		t.Errorf("populated profile changed: %v", preset.Architectures)
	}

	empty := &specs.LinuxSeccomp{DefaultAction: specs.ActErrno}
	err = seccomp.PopulateNativeArchitecture(empty)

	native, ok := seccomp.NativeArchitecture()
	if !ok {
		if !errors.Is(err, seccomp.ErrUnknownNativeArchitecture) {
			t.Errorf("unknown GOARCH: expected ErrUnknownNativeArchitecture, got %v", err)
		}

		return
	}

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !slices.Equal(empty.Architectures, []specs.Arch{native}) {
		t.Errorf("architectures = %v, want [%s]", empty.Architectures, native)
	}
}
