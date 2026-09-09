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

package landlock_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestJSONRoundTripFull(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessConnectTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
			{
				Path: pathTmp,
				AccessFS: []landlock.FSAccessRight{
					landlock.FSAccessReadFile,
					landlock.FSAccessWriteFile,
				},
			},
		},
		NetRules: []landlock.NetRule{
			{
				Port:      80,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
			},
			{
				Port:      443,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
			},
		},
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripScoped(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeAbstractUnixSocket,
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripEmpty(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripFSOnly(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathHome,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
		},
		NetRules: nil,
	}

	assertJSONRoundTrip(t, &profile)
}

func TestJSONRoundTripEmptyAccessLists(t *testing.T) {
	t.Parallel()

	profile := landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{},
		HandledAccessNet: []landlock.NetAccessRight{},
		Scoped:           nil,
		PathRules:        []landlock.PathRule{},
		NetRules:         []landlock.NetRule{},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got landlock.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.HandledAccessFS != nil || got.HandledAccessNet != nil ||
		got.PathRules != nil || got.NetRules != nil {
		t.Error("expected nil slices after round-trip of empty slices (omitempty)")
	}
}

func assertJSONRoundTrip(t *testing.T, profile *landlock.Profile) {
	t.Helper()

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got landlock.Profile

	err = json.Unmarshal(data, &got)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !reflect.DeepEqual(*profile, got) {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", got, *profile)
	}
}
