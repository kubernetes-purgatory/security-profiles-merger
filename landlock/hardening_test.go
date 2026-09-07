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
	"errors"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/landlock"
)

// readFileProfile builds a profile handling read_file with the given rules.
func readFileProfile(rules []landlock.PathRule) *landlock.Profile {
	return &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        rules,
		NetRules:         nil,
	}
}

func TestMergePrunesUnhandledRights(t *testing.T) {
	t.Parallel()

	readWrite := []landlock.FSAccessRight{landlock.FSAccessReadFile, landlock.FSAccessWriteFile}
	bindConnect := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
	}

	wide := &landlock.Profile{
		HandledAccessFS:  readWrite,
		HandledAccessNet: bindConnect,
		Scoped:           nil,
		PathRules:        []landlock.PathRule{{Path: "/etc", AccessFS: readWrite}},
		NetRules:         []landlock.NetRule{{Port: 443, AccessNet: bindConnect}},
	}
	narrow := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: "/etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: []landlock.NetRule{{
			Port: 443, AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
		}},
	}

	result, err := landlock.Union(wide, narrow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "Profile{fs:read_file net:connect_tcp /etc(read_file) :443(connect_tcp)}"
	if got := landlock.FormatProfile(result); got != want {
		t.Errorf("Union = %s, want %s", got, want)
	}

	err = landlock.ValidateStrict(result)
	if err != nil {
		t.Errorf("ValidateStrict(Union) = %v, want nil", err)
	}

	// A rule granting only unhandled rights disappears entirely.
	noop := readFileProfile([]landlock.PathRule{{
		Path: "/tmp", AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
	}})

	result, err = landlock.Intersect(noop, noop)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PathRules != nil {
		t.Errorf("Intersect kept a rule without handled rights: %s", landlock.FormatProfile(result))
	}
}

func TestSingleAndPairwiseMergeAgree(t *testing.T) {
	t.Parallel()

	profile := readFileProfile(nil)

	single, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pair, err := landlock.Intersect(profile, profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if single.PathRules != nil || pair.PathRules != nil {
		t.Errorf("PathRules = %v and %v, want nil for both", single.PathRules, pair.PathRules)
	}
}

func TestValidateDetectsDuplicatesAfterCleaning(t *testing.T) {
	t.Parallel()

	profile := readFileProfile([]landlock.PathRule{
		{Path: "/etc", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
		{Path: "/etc/", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile}},
	})

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("Validate = %v, want ErrDuplicateRule", err)
	}
}

func TestValidateRejectsPathsResolvingToDot(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"a/..", "./", "."} {
		profile := readFileProfile([]landlock.PathRule{{
			Path: path, AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}})

		err := landlock.Validate(profile)
		if !errors.Is(err, landlock.ErrEmptyPath) {
			t.Errorf("Validate(%q) = %v, want ErrEmptyPath", path, err)
		}

		_, err = landlock.Intersect(profile)
		if !errors.Is(err, landlock.ErrEmptyPath) {
			t.Errorf("Intersect(%q) = %v, want ErrEmptyPath", path, err)
		}
	}
}

func TestValidateRejectsNulByte(t *testing.T) {
	t.Parallel()

	profile := readFileProfile([]landlock.PathRule{{
		Path: "/etc\x00x", AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
	}})

	err := landlock.Validate(profile)
	if !errors.Is(err, landlock.ErrInvalidPath) {
		t.Errorf("Validate = %v, want ErrInvalidPath", err)
	}

	err = landlock.ValidateStrict(profile)
	if !errors.Is(err, landlock.ErrInvalidPath) {
		t.Errorf("ValidateStrict = %v, want ErrInvalidPath", err)
	}
}
