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
	"strings"
	"testing"

	"sigs.k8s.io/security-profiles-merger/landlock"
)

func TestValidateNil(t *testing.T) {
	t.Parallel()

	err := landlock.Validate(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}
}

func TestValidateValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			},
		}},
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownHandledFS(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_right"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown HandledAccessFS")
	}
}

func TestValidateUnknownHandledNet(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown HandledAccessNet")
	}
}

func TestValidateUnknownPathRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{"read_bogus"},
		}},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown path rule right")
	}
}

func TestValidateUnknownNetRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{"bind_bogus"},
		}},
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown net rule right")
	}
}

func TestValidateEmpty(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error for empty profile: %v", err)
	}
}

func TestValidateMultipleErrors(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_fs"},
		HandledAccessNet: []landlock.NetAccessRight{"bogus_net"},
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{"read_bogus"},
		}},
		NetRules: []landlock.NetRule{{
			Port:      80,
			AccessNet: []landlock.NetAccessRight{"bind_bogus"},
		}},
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for multiple invalid rights")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}

	msg := err.Error()

	for _, want := range []string{
		"HandledAccessFS", "HandledAccessNet",
		"PathRules[0]", "NetRules[0]",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should mention %s: %v", want, err)
		}
	}
}

func TestValidateDuplicatePathRule(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
			},
			{
				Path:     pathEtc,
				AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
			},
		},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate path rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

func TestValidateDuplicateNetRule(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{
			{
				Port:      443,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessBindTCP},
			},
			{
				Port:      443,
				AccessNet: []landlock.NetAccessRight{landlock.NetAccessConnectTCP},
			},
		},
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate net rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRule) {
		t.Errorf("expected ErrDuplicateRule, got: %v", err)
	}
}

func TestValidateEmptyPath(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for empty path")
	}

	if !errors.Is(err, landlock.ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got: %v", err)
	}
}

func TestValidateStrictNil(t *testing.T) {
	t.Parallel()

	err := landlock.ValidateStrict(nil)
	if err == nil {
		t.Fatal("expected error for nil profile")
	}

	if !errors.Is(err, landlock.ErrNilProfile) {
		t.Errorf("expected ErrNilProfile, got: %v", err)
	}
}

func TestValidateStrictInvalidProfile(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for invalid profile")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}
}

func TestValidateStrictValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped: nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
			},
		}},
	}

	err := landlock.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateStrictUnhandledPathRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unhandled path right")
	}

	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Errorf("expected ErrUnhandledRight, got: %v", err)
	}
}

func TestValidateStrictUnhandledNetRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessConnectTCP,
			},
		}},
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for unhandled net right")
	}

	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Errorf("expected ErrUnhandledRight, got: %v", err)
	}
}

func TestValidateStrictCollectsAllErrors(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     pathEtc,
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessWriteFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error from ValidateStrict")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}

	if !errors.Is(err, landlock.ErrUnhandledRight) {
		t.Error("expected ErrUnhandledRight alongside Validate errors")
	}
}

func TestValidateStrictRelativePath(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "relative/path",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err == nil {
		t.Fatal("expected error for relative path")
	}

	if !errors.Is(err, landlock.ErrRelativePath) {
		t.Errorf("expected ErrRelativePath, got: %v", err)
	}
}

func TestValidateStrictAbsolutePathValid(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{landlock.FSAccessReadFile},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path:     "/absolute/path",
			AccessFS: []landlock.FSAccessRight{landlock.FSAccessReadFile},
		}},
		NetRules: nil,
	}

	err := landlock.ValidateStrict(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAllKnownFSRights(t *testing.T) {
	t.Parallel()

	all := []landlock.FSAccessRight{
		landlock.FSAccessExecute,
		landlock.FSAccessWriteFile,
		landlock.FSAccessReadFile,
		landlock.FSAccessReadDir,
		landlock.FSAccessRemoveDir,
		landlock.FSAccessRemoveFile,
		landlock.FSAccessMakeChar,
		landlock.FSAccessMakeDir,
		landlock.FSAccessMakeReg,
		landlock.FSAccessMakeSock,
		landlock.FSAccessMakeFIFO,
		landlock.FSAccessMakeSym,
		landlock.FSAccessMakeBlock,
		landlock.FSAccessRefer,
		landlock.FSAccessTruncate,
		landlock.FSAccessIOCTLDev,
		landlock.FSAccessResolveUnix,
		landlock.FSAccessCreateTmp,
	}

	profile := &landlock.Profile{
		HandledAccessFS:  all,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAllKnownNetRights(t *testing.T) {
	t.Parallel()

	all := []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
		landlock.NetAccessBindUDP,
		landlock.NetAccessConnectSendUDP,
		landlock.NetAccessListenTCP,
		landlock.NetAccessAcceptTCP,
	}

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: all,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAllKnownScopeRights(t *testing.T) {
	t.Parallel()

	all := []landlock.ScopeRight{
		landlock.ScopeAbstractUnixSocket,
		landlock.ScopeSignal,
	}

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           all,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateUnknownScopeRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           []landlock.ScopeRight{"bogus_scope"},
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for unknown scope right")
	}

	if !errors.Is(err, landlock.ErrUnknownRight) {
		t.Errorf("expected ErrUnknownRight, got: %v", err)
	}
}

func TestValidateDuplicateScopeRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped: []landlock.ScopeRight{
			landlock.ScopeSignal,
			landlock.ScopeSignal,
		},
		PathRules: nil,
		NetRules:  nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate scope right")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicateFSRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate FS right in handled set")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicateHandledAccessNet(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS: nil,
		HandledAccessNet: []landlock.NetAccessRight{
			landlock.NetAccessBindTCP,
			landlock.NetAccessBindTCP,
		},
		Scoped:    nil,
		PathRules: nil,
		NetRules:  nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate HandledAccessNet right")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicateNetRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules: []landlock.NetRule{{
			Port: 80,
			AccessNet: []landlock.NetAccessRight{
				landlock.NetAccessBindTCP,
				landlock.NetAccessBindTCP,
			},
		}},
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate net right in rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}

func TestValidateDuplicatePathRuleRight(t *testing.T) {
	t.Parallel()

	profile := &landlock.Profile{
		HandledAccessFS:  nil,
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	err := landlock.Validate(profile)
	if err == nil {
		t.Fatal("expected error for duplicate FS right in path rule")
	}

	if !errors.Is(err, landlock.ErrDuplicateRight) {
		t.Errorf("expected ErrDuplicateRight, got: %v", err)
	}
}
