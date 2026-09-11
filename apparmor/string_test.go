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
	"testing"

	"sigs.k8s.io/security-profiles-merger/apparmor"
)

func TestProfileString(t *testing.T) {
	t.Parallel()

	allowRaw := true
	allowTCP := true
	allowUDP := false

	profile := apparmor.Profile{
		Executable: &apparmor.ExecutableRules{
			AllowedExecutables: []string{"/usr/bin/ls"},
			AllowedLibraries:   []string{"/usr/lib/libc.so"},
		},
		Filesystem: &apparmor.FilesystemRules{
			ReadOnlyPaths:  []string{pathEtcPasswd},
			WriteOnlyPaths: nil,
			ReadWritePaths: []string{"/tmp"},
		},
		Network: &apparmor.NetworkRules{
			AllowRaw: &allowRaw,
			Protocols: &apparmor.AllowedProtocols{
				AllowTCP: &allowTCP,
				AllowUDP: &allowUDP,
			},
		},
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin, capSysTime},
		},
	}

	const want = "Profile{exec:/usr/bin/ls lib:/usr/lib/libc.so " +
		"r:/etc/passwd rw:/tmp net:raw,tcp,!udp caps:NET_ADMIN,SYS_TIME}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestProfileStringEmpty(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable:   nil,
		Filesystem:   nil,
		Network:      nil,
		Capabilities: nil,
	}

	const want = "Profile{}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestExecutableRulesString(t *testing.T) {
	t.Parallel()

	rules := apparmor.ExecutableRules{
		AllowedExecutables: []string{"/bin/cat", "/bin/ls"},
		AllowedLibraries:   []string{pathLibCStd},
	}

	const want = "exec:/bin/cat,/bin/ls lib:" + pathLibCStd

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestFilesystemRulesString(t *testing.T) {
	t.Parallel()

	rules := apparmor.FilesystemRules{
		ReadOnlyPaths:  []string{pathEtcPasswd},
		WriteOnlyPaths: []string{"/var/log"},
		ReadWritePaths: []string{"/tmp"},
	}

	const want = "r:/etc/passwd w:/var/log rw:/tmp"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestNetworkRulesString(t *testing.T) {
	t.Parallel()

	allowRaw := false
	allowTCP := true
	allowUDP := true

	rules := apparmor.NetworkRules{
		AllowRaw: &allowRaw,
		Protocols: &apparmor.AllowedProtocols{
			AllowTCP: &allowTCP,
			AllowUDP: &allowUDP,
		},
	}

	const want = "net:!raw,tcp,udp"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCapabilityRulesString(t *testing.T) {
	t.Parallel()

	rules := apparmor.CapabilityRules{
		AllowedCapabilities: []string{capChown, capDacOverride},
	}

	const want = "caps:CHOWN,DAC_OVERRIDE"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestCapabilityRulesStringEmpty(t *testing.T) {
	t.Parallel()

	rules := apparmor.CapabilityRules{
		AllowedCapabilities: nil,
	}

	const want = "caps:none"

	if got := rules.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestNetworkRulesStringEmpty(t *testing.T) {
	t.Parallel()

	rules := apparmor.NetworkRules{
		AllowRaw:  nil,
		Protocols: nil,
	}

	if got := rules.String(); got != "" {
		t.Errorf("String() = %q, want empty string", got)
	}
}

func TestNetworkRulesStringEmptyProtocols(t *testing.T) {
	t.Parallel()

	rules := apparmor.NetworkRules{
		AllowRaw: nil,
		Protocols: &apparmor.AllowedProtocols{
			AllowTCP: nil,
			AllowUDP: nil,
		},
	}

	if got := rules.String(); got != "" {
		t.Errorf("String() = %q, want empty string", got)
	}
}

func TestProfileStringWithEmptyNetwork(t *testing.T) {
	t.Parallel()

	profile := apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network: &apparmor.NetworkRules{
			AllowRaw:  nil,
			Protocols: nil,
		},
		Capabilities: nil,
	}

	const want = "Profile{}"

	if got := profile.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestFormatProfileNil(t *testing.T) {
	t.Parallel()

	const want = "Profile{<nil>}"

	if got := apparmor.FormatProfile(nil); got != want {
		t.Errorf("FormatProfile(nil) = %q, want %q", got, want)
	}
}

func TestFormatProfileNonNil(t *testing.T) {
	t.Parallel()

	profile := &apparmor.Profile{
		Executable: nil,
		Filesystem: nil,
		Network:    nil,
		Capabilities: &apparmor.CapabilityRules{
			AllowedCapabilities: []string{capNetAdmin},
		},
	}

	const want = "Profile{caps:NET_ADMIN}"

	if got := apparmor.FormatProfile(profile); got != want {
		t.Errorf("FormatProfile() = %q, want %q", got, want)
	}
}
