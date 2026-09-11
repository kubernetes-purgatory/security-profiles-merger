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
	"encoding/json"
	"reflect"
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestJSONRoundTripFull(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathBinBash, pathBinCurl},
			AllowedLibraries:   []string{pathLibC, pathLibM},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathVarLog},
			ReadWritePaths: []string{pathTmp},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: boolPtr(true),
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: boolPtr(true),
				AllowUDP: boolPtr(false),
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	assertJSONRoundTrip(t, profile)
}

func TestJSONRoundTripNilFields(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	assertJSONRoundTrip(t, profile)
}

func TestJSONRoundTripEmptySubStructs(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: nil,
			AllowedLibraries:   nil,
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  nil,
			WriteOnlyPaths: nil,
			ReadWritePaths: nil,
		},
		Network: &apparmor.NetworkRules{
			AllowRaw:  nil,
			Protocols: nil,
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: nil,
		},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got apparmor.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.Executable == nil {
		t.Error("expected non-nil Executable after round-trip of empty struct")
	}

	if got.Filesystem == nil {
		t.Error("expected non-nil Filesystem after round-trip of empty struct")
	}

	if got.Network == nil {
		t.Error("expected non-nil Network after round-trip of empty struct")
	}

	if got.Capabilities == nil {
		t.Error("expected non-nil Capabilities after round-trip of empty struct")
	}
}

func TestJSONRoundTripPartialFields(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  boolPtr(false),
			Protocols: nil,
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capChown},
		},
	}

	assertJSONRoundTrip(t, profile)
}

func assertJSONRoundTrip(t *testing.T, profile apparmor.Profile) {
	t.Helper()

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got apparmor.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(profile, got) {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", got, profile)
	}
}
