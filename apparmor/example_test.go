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
	"fmt"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func ExampleIntersect() {
	base := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime, capChown},
		},
	}

	oci := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	result, err := apparmor.Intersect(base, oci)
	if err != nil {
		panic(err)
	}

	fmt.Println("Capabilities:", result.Capabilities.AllowedCapabilities)

	// Output:
	// Capabilities: [CHOWN NET_ADMIN]
}

func ExampleValidate() {
	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcConfig},
			WriteOnlyPaths: []string{pathEtcConfig},
			ReadWritePaths: nil,
		},
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.Validate(profile)
	fmt.Println(err)

	// Output:
	// path "/etc/config" in both ReadOnlyPaths and WriteOnlyPaths: duplicate path across filesystem categories
}

func ExampleValidate_emptyCapability() {
	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, ""},
		},
	}

	err := apparmor.Validate(profile)
	fmt.Println(err)

	// Output:
	// AllowedCapabilities[1]: empty capability
}

func ExampleValidateStrict() {
	profile := &apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{pathEtcConfig, pathEtcConfig},
			AllowedLibraries:   nil,
		},
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	err := apparmor.ValidateStrict(profile)
	fmt.Println(err)

	// Output:
	// AllowedExecutables: "/etc/config": duplicate executable path
}

func ExampleFormatProfile() {
	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	fmt.Println(apparmor.FormatProfile(profile))

	// Output:
	// Profile{caps:NET_ADMIN}
}

func ExampleDiff() {
	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("Equal:", diff.Equal)
	fmt.Println("Removed:", diff.Capabilities.Removed)
	fmt.Println("Added:", diff.Capabilities.Added)

	// Output:
	// Equal: false
	// Removed: [SYS_TIME]
	// Added: [CHOWN]
}

func ExampleFormatDiff() {
	left := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	right := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capChown},
		},
	}

	diff, err := apparmor.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println(apparmor.FormatDiff(diff))

	// Output:
	// Diff{caps:-SYS_TIME,+CHOWN}
}

func ExampleIsGlobPattern() {
	fmt.Println(apparmor.IsGlobPattern("/usr/lib/**"))
	fmt.Println(apparmor.IsGlobPattern("/usr/bin/bash"))

	// Output:
	// true
	// false
}

func ExampleUnion() {
	recording1 := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	recording2 := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	result, err := apparmor.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("Capabilities:", result.Capabilities.AllowedCapabilities)

	// Output:
	// Capabilities: [NET_ADMIN SYS_TIME]
}
