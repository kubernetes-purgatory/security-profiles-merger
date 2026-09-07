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
	"cmp"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/saschagrunert/security-profiles-merger/landlock"
)

func allFSRightsForFuzz() []landlock.FSAccessRight {
	return []landlock.FSAccessRight{
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
}

func allNetRightsForFuzz() []landlock.NetAccessRight {
	return []landlock.NetAccessRight{
		landlock.NetAccessBindTCP,
		landlock.NetAccessConnectTCP,
		landlock.NetAccessBindUDP,
		landlock.NetAccessConnectSendUDP,
		landlock.NetAccessListenTCP,
		landlock.NetAccessAcceptTCP,
	}
}

func allScopeRightsForFuzz() []landlock.ScopeRight {
	return []landlock.ScopeRight{
		landlock.ScopeAbstractUnixSocket,
		landlock.ScopeSignal,
	}
}

func fuzzLandlockProfile(
	handledFSMask uint32, handledNetMask uint8, scopeMask uint8,
	path1, path2 string,
	accessMask1, accessMask2 uint32,
	port1, port2 uint16,
	netMask1, netMask2 uint8,
) *landlock.Profile {
	handledFS := pickFSRights(handledFSMask)
	handledNet := pickNetRights(handledNetMask)
	scoped := pickScopeRights(scopeMask)

	path1 = fuzzPath(path1, "/default1")
	path2 = fuzzPath(path2, "/default2")

	pathRules := buildFuzzPathRules(
		path1, path2,
		accessMask1&handledFSMask, accessMask2&handledFSMask,
	)
	netRules := buildFuzzNetRules(
		port1, port2, netMask1&handledNetMask, netMask2&handledNetMask,
	)

	return &landlock.Profile{
		HandledAccessFS:  handledFS,
		HandledAccessNet: handledNet,
		Scoped:           scoped,
		PathRules:        pathRules,
		NetRules:         netRules,
	}
}

// fuzzPath cleans a fuzz-generated path and substitutes the fallback for
// inputs Validate rejects: empty paths, paths that clean to ".", and paths
// with NUL bytes.
func fuzzPath(path, fallback string) string {
	path = filepath.Clean(strings.ReplaceAll(path, "\x00", ""))
	if path == "." {
		return fallback
	}

	return path
}

func buildFuzzPathRules(
	path1, path2 string,
	accessMask1, accessMask2 uint32,
) []landlock.PathRule {
	var pathRules []landlock.PathRule

	if access := pickFSRights(accessMask1); len(access) > 0 {
		pathRules = append(pathRules, landlock.PathRule{
			Path:     path1,
			AccessFS: access,
		})
	}

	if path2 != path1 {
		if access := pickFSRights(accessMask2); len(access) > 0 {
			pathRules = append(pathRules, landlock.PathRule{
				Path:     path2,
				AccessFS: access,
			})
		}
	}

	return pathRules
}

func buildFuzzNetRules(
	port1, port2 uint16,
	netMask1, netMask2 uint8,
) []landlock.NetRule {
	var netRules []landlock.NetRule

	if access := pickNetRights(netMask1); len(access) > 0 {
		netRules = append(netRules, landlock.NetRule{
			Port:      port1,
			AccessNet: access,
		})
	}

	if port2 != port1 {
		if access := pickNetRights(netMask2); len(access) > 0 {
			netRules = append(netRules, landlock.NetRule{
				Port:      port2,
				AccessNet: access,
			})
		}
	}

	return netRules
}

func pickFSRights(mask uint32) []landlock.FSAccessRight {
	all := allFSRightsForFuzz()

	var rights []landlock.FSAccessRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func pickNetRights(mask uint8) []landlock.NetAccessRight {
	all := allNetRightsForFuzz()

	var rights []landlock.NetAccessRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func pickScopeRights(mask uint8) []landlock.ScopeRight {
	all := allScopeRightsForFuzz()

	var rights []landlock.ScopeRight

	for idx, right := range all {
		if mask&(1<<idx) != 0 {
			rights = append(rights, right)
		}
	}

	return rights
}

func addLandlockFuzzSeeds(f *testing.F) {
	f.Helper()

	// Baseline: overlapping paths.
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x03),
		"/etc", "/home",
		uint32(0x05), uint32(0x03),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x07), uint8(0x03), uint8(0x01),
		"/etc", "/tmp",
		uint32(0x01), uint32(0x06),
		uint16(80), uint16(8080),
		uint8(0x03), uint8(0x01),
	)

	// Identical profiles.
	f.Add(
		uint32(0x03), uint8(0x01), uint8(0x02),
		"/etc", "/home",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x03), uint8(0x01), uint8(0x02),
		"/etc", "/home",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)

	// Disjoint paths.
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x00),
		"/a", "/b",
		uint32(0x01), uint32(0x02),
		uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03),
		"/c", "/d",
		uint32(0x04), uint32(0x08),
		uint16(8080), uint16(9090),
		uint8(0x01), uint8(0x02),
	)

	// All FS rights handled, empty access lists.
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03),
		"/etc", "/home",
		uint32(0x00), uint32(0x00),
		uint16(80), uint16(443),
		uint8(0x00), uint8(0x00),
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03),
		"/etc", "/tmp",
		uint32(0x00), uint32(0x00),
		uint16(80), uint16(8080),
		uint8(0x00), uint8(0x00),
	)

	// Same ports, same paths (identical rules)
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x00),
		"/etc", "/etc",
		uint32(0x01), uint32(0x01),
		uint16(80), uint16(80),
		uint8(0x01), uint8(0x01),
		uint32(0x07), uint8(0x03), uint8(0x00),
		"/etc", "/etc",
		uint32(0x01), uint32(0x01),
		uint16(80), uint16(80),
		uint8(0x01), uint8(0x01),
	)

	// Single FS right, single scope, no net
	f.Add(
		uint32(0x01), uint8(0x00), uint8(0x01),
		"/a", "/b",
		uint32(0x01), uint32(0x00),
		uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
		uint32(0x01), uint8(0x00), uint8(0x02),
		"/a", "/c",
		uint32(0x01), uint32(0x00),
		uint16(0), uint16(0),
		uint8(0x00), uint8(0x00),
	)
}

type fuzzMergeConfig struct {
	merge    func(...*landlock.Profile) (*landlock.Profile, error)
	checkInv func(*testing.T, *landlock.Profile, *landlock.Profile, *landlock.Profile)
	equal    func(*landlock.Profile, *landlock.Profile) bool
}

func fuzzMerge(
	t *testing.T,
	cfg fuzzMergeConfig,
	hfsL uint32, hnetL uint8, scopeL uint8,
	p1L, p2L string,
	am1L, am2L uint32,
	port1L, port2L uint16,
	nm1L, nm2L uint8,
	hfsR uint32, hnetR uint8, scopeR uint8,
	p1R, p2R string,
	am1R, am2R uint32,
	port1R, port2R uint16,
	nm1R, nm2R uint8,
) {
	t.Helper()

	left := fuzzLandlockProfile(
		hfsL, hnetL, scopeL, p1L, p2L,
		am1L, am2L, port1L, port2L, nm1L, nm2L,
	)
	right := fuzzLandlockProfile(
		hfsR, hnetR, scopeR, p1R, p2R,
		am1R, am2R, port1R, port2R, nm1R, nm2R,
	)

	result, err := cfg.merge(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if result == nil {
		t.Fatal("result must not be nil")
	}

	cfg.checkInv(t, result, left, right)

	commuted, err := cfg.merge(right, left)
	if err != nil {
		t.Fatalf("commuted merge: %v", err)
	}

	if !profilesEqual(result, commuted) {
		t.Error("Merge(L,R) != Merge(R,L)")
	}

	single, err := cfg.merge(left)
	if err != nil {
		t.Fatalf("single merge: %v", err)
	}

	idempotent, err := cfg.merge(left, left)
	if err != nil {
		t.Fatalf("idempotent merge: %v", err)
	}

	if !cfg.equal(idempotent, single) {
		t.Errorf(
			"Merge(X,X) should equal Merge(X)\n  got:  %s\n  want: %s",
			landlock.FormatProfile(idempotent),
			landlock.FormatProfile(single),
		)
	}
}

// semanticallyEqual compares two profiles by the access they permit rather
// than by rule structure: handled and scoped sets must match, and every path
// or port named by either profile must permit the same rights.
func semanticallyEqual(left, right *landlock.Profile) bool {
	if !slices.Equal(left.HandledAccessFS, right.HandledAccessFS) ||
		!slices.Equal(left.HandledAccessNet, right.HandledAccessNet) ||
		!slices.Equal(left.Scoped, right.Scoped) {
		return false
	}

	for _, rule := range slices.Concat(left.PathRules, right.PathRules) {
		for _, access := range allFSRights() {
			if fsPermits(left, rule.Path, access) != fsPermits(right, rule.Path, access) {
				return false
			}
		}
	}

	for _, rule := range slices.Concat(left.NetRules, right.NetRules) {
		for _, access := range allNetRights() {
			if netPermits(left, rule.Port, access) != netPermits(right, rule.Port, access) {
				return false
			}
		}
	}

	return true
}

func fsRightSet(rights []landlock.FSAccessRight) map[landlock.FSAccessRight]struct{} {
	set := make(map[landlock.FSAccessRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func netRightSet(rights []landlock.NetAccessRight) map[landlock.NetAccessRight]struct{} {
	set := make(map[landlock.NetAccessRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func scopeRightSet(rights []landlock.ScopeRight) map[landlock.ScopeRight]struct{} {
	set := make(map[landlock.ScopeRight]struct{}, len(rights))
	for _, r := range rights {
		set[r] = struct{}{}
	}

	return set
}

func pathRuleMap(rules []landlock.PathRule) map[string][]landlock.FSAccessRight {
	result := make(map[string][]landlock.FSAccessRight, len(rules))
	for _, rule := range rules {
		result[rule.Path] = rule.AccessFS
	}

	return result
}

func netRulePortMap(
	rules []landlock.NetRule,
) map[uint16][]landlock.NetAccessRight {
	result := make(map[uint16][]landlock.NetAccessRight, len(rules))
	for _, rule := range rules {
		result[rule.Port] = rule.AccessNet
	}

	return result
}

func assertIntersectInvariants(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertPathsFromInputs(t, result, left, right)
	assertIntersectPathsExact(t, result, left, right)
	assertIntersectNetExact(t, result, left, right)
	assertHandledFromInputs(t, result, left, right)
	assertHandledCoversInputs(t, result, left, right)
	assertIntersectScopedCoversInputs(t, result, left, right)
}

func assertPathsFromInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	inputPaths := make(map[string]struct{})
	for _, rule := range left.PathRules {
		inputPaths[rule.Path] = struct{}{}
	}

	for _, rule := range right.PathRules {
		inputPaths[rule.Path] = struct{}{}
	}

	for _, rule := range result.PathRules {
		if _, ok := inputPaths[rule.Path]; !ok {
			t.Errorf("result contains path %q not in any input", rule.Path)
		}
	}
}

func assertHandledFromInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftHandledFS := fsRightSet(left.HandledAccessFS)
	rightHandledFS := fsRightSet(right.HandledAccessFS)

	for _, r := range result.HandledAccessFS {
		if _, inL := leftHandledFS[r]; !inL {
			if _, inR := rightHandledFS[r]; !inR {
				t.Errorf("intersect handled FS right %q not in either input", r)
			}
		}
	}

	leftHandledNet := netRightSet(left.HandledAccessNet)
	rightHandledNet := netRightSet(right.HandledAccessNet)

	for _, r := range result.HandledAccessNet {
		if _, inL := leftHandledNet[r]; !inL {
			if _, inR := rightHandledNet[r]; !inR {
				t.Errorf("intersect handled Net right %q not in either input", r)
			}
		}
	}
}

func assertHandledCoversInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertHandledCoversInputsFS(t, result, left, right)
	assertHandledCoversInputsNet(t, result, left, right)
}

func assertHandledCoversInputsFS(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultFS := fsRightSet(result.HandledAccessFS)

	for _, r := range left.HandledAccessFS {
		if _, ok := resultFS[r]; !ok {
			t.Errorf("intersect handled FS missing left input right %q", r)
		}
	}

	for _, r := range right.HandledAccessFS {
		if _, ok := resultFS[r]; !ok {
			t.Errorf("intersect handled FS missing right input right %q", r)
		}
	}
}

func assertHandledCoversInputsNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultNet := netRightSet(result.HandledAccessNet)

	for _, r := range left.HandledAccessNet {
		if _, ok := resultNet[r]; !ok {
			t.Errorf("intersect handled Net missing left input right %q", r)
		}
	}

	for _, r := range right.HandledAccessNet {
		if _, ok := resultNet[r]; !ok {
			t.Errorf("intersect handled Net missing right input right %q", r)
		}
	}
}

func assertIntersectScopedCoversInputs(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultScoped := scopeRightSet(result.Scoped)

	for _, r := range left.Scoped {
		if _, ok := resultScoped[r]; !ok {
			t.Errorf("intersect scoped missing left input right %q", r)
		}
	}

	for _, r := range right.Scoped {
		if _, ok := resultScoped[r]; !ok {
			t.Errorf("intersect scoped missing right input right %q", r)
		}
	}
}

func assertUnionScopedSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftScoped := scopeRightSet(left.Scoped)
	rightScoped := scopeRightSet(right.Scoped)

	for _, r := range result.Scoped {
		_, inL := leftScoped[r]
		_, inR := rightScoped[r]

		if !inL || !inR {
			t.Errorf("union scoped right %q not in both inputs", r)
		}
	}
}

func assertUnionScopedCoversCommon(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultScoped := scopeRightSet(result.Scoped)
	rightScoped := scopeRightSet(right.Scoped)

	for _, scopeRight := range left.Scoped {
		if _, inR := rightScoped[scopeRight]; !inR {
			continue
		}

		if _, ok := resultScoped[scopeRight]; !ok {
			t.Errorf("union scoped missing common right %q", scopeRight)
		}
	}
}

// fsPermits reports whether a profile permits a filesystem right under a
// path: either the right is unhandled, or a rule on the path or one of its
// ancestors grants it.
func fsPermits(profile *landlock.Profile, path string, right landlock.FSAccessRight) bool {
	if _, handled := fsRightSet(profile.HandledAccessFS)[right]; !handled {
		return true
	}

	for _, rule := range profile.PathRules {
		if !landlock.IsAncestorOrSelf(rule.Path, path) {
			continue
		}

		if slices.Contains(rule.AccessFS, right) {
			return true
		}
	}

	return false
}

// netPermits reports whether a profile permits a network right on a port:
// either the right is unhandled, or the rule for the port grants it.
func netPermits(profile *landlock.Profile, port uint16, right landlock.NetAccessRight) bool {
	if _, handled := netRightSet(profile.HandledAccessNet)[right]; !handled {
		return true
	}

	return slices.Contains(netRulePortMap(profile.NetRules)[port], right)
}

// assertIntersectPathsExact checks that every right in the result is
// permitted by both inputs at its path, and that every right both inputs
// permit at an input path appears in the result.
func assertIntersectPathsExact(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	normLeft := normalized(t, left)
	normRight := normalized(t, right)

	for _, rule := range result.PathRules {
		for _, access := range rule.AccessFS {
			if !fsPermits(normLeft, rule.Path, access) || !fsPermits(normRight, rule.Path, access) {
				t.Errorf(
					"intersect path %q has right %q not permitted by both inputs",
					rule.Path, access,
				)
			}
		}
	}

	resultPaths := pathRuleMap(result.PathRules)

	for _, rule := range slices.Concat(normLeft.PathRules, normRight.PathRules) {
		assertPathRightsComplete(t, rule.Path, resultPaths[rule.Path], normLeft, normRight)
	}
}

func assertPathRightsComplete(
	t *testing.T,
	path string,
	granted []landlock.FSAccessRight,
	left, right *landlock.Profile,
) {
	t.Helper()

	for _, access := range allFSRights() {
		expected := fsPermits(left, path, access) &&
			fsPermits(right, path, access) &&
			fsRuleGrants(left, right, path, access)

		if expected && !slices.Contains(granted, access) {
			t.Errorf("intersect path %q is missing right %q", path, access)
		}
	}
}

// fsRuleGrants reports whether at least one input grants the right through a
// rule (rather than by leaving it unhandled), which is required for the
// right to appear in the result.
func fsRuleGrants(
	left, right *landlock.Profile, path string, access landlock.FSAccessRight,
) bool {
	for _, rule := range slices.Concat(left.PathRules, right.PathRules) {
		if landlock.IsAncestorOrSelf(rule.Path, path) && slices.Contains(rule.AccessFS, access) {
			return true
		}
	}

	return false
}

// assertIntersectNetExact mirrors assertIntersectPathsExact for ports.
func assertIntersectNetExact(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	normLeft := normalized(t, left)
	normRight := normalized(t, right)

	for _, rule := range result.NetRules {
		for _, access := range rule.AccessNet {
			if !netPermits(normLeft, rule.Port, access) ||
				!netPermits(normRight, rule.Port, access) {
				t.Errorf(
					"intersect port %d has right %q not permitted by both inputs",
					rule.Port, access,
				)
			}
		}
	}

	resultPorts := netRulePortMap(result.NetRules)

	for _, rule := range slices.Concat(normLeft.NetRules, normRight.NetRules) {
		assertNetRightsComplete(t, rule.Port, resultPorts[rule.Port], normLeft, normRight)
	}
}

func assertNetRightsComplete(
	t *testing.T,
	port uint16,
	granted []landlock.NetAccessRight,
	left, right *landlock.Profile,
) {
	t.Helper()

	leftRule := netRulePortMap(left.NetRules)[port]
	rightRule := netRulePortMap(right.NetRules)[port]

	for _, access := range allNetRights() {
		expected := netPermits(left, port, access) &&
			netPermits(right, port, access) &&
			(slices.Contains(leftRule, access) || slices.Contains(rightRule, access))

		if expected && !slices.Contains(granted, access) {
			t.Errorf("intersect port %d is missing right %q", port, access)
		}
	}
}

// normalized returns the profile as the merge sees it: paths cleaned and
// duplicate rules folded, obtained by intersecting the profile with itself.
func normalized(t *testing.T, profile *landlock.Profile) *landlock.Profile {
	t.Helper()

	result, err := landlock.Intersect(profile)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	return result
}

func allFSRights() []landlock.FSAccessRight {
	return []landlock.FSAccessRight{
		landlock.FSAccessExecute, landlock.FSAccessWriteFile, landlock.FSAccessReadFile,
		landlock.FSAccessReadDir, landlock.FSAccessRemoveDir, landlock.FSAccessRemoveFile,
		landlock.FSAccessMakeChar, landlock.FSAccessMakeDir, landlock.FSAccessMakeReg,
		landlock.FSAccessMakeSock, landlock.FSAccessMakeFIFO, landlock.FSAccessMakeSym,
		landlock.FSAccessMakeBlock, landlock.FSAccessRefer, landlock.FSAccessTruncate,
		landlock.FSAccessIOCTLDev, landlock.FSAccessResolveUnix, landlock.FSAccessCreateTmp,
	}
}

func allNetRights() []landlock.NetAccessRight {
	return []landlock.NetAccessRight{
		landlock.NetAccessBindTCP, landlock.NetAccessConnectTCP,
		landlock.NetAccessBindUDP, landlock.NetAccessConnectSendUDP,
		landlock.NetAccessListenTCP, landlock.NetAccessAcceptTCP,
	}
}

func assertUnionInvariants(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertUnionPathCoverage(t, result, left, right)
	assertUnionPathRightsSuperset(t, result, left, right)
	assertUnionNetRightsSuperset(t, result, left, right)
	assertUnionHandledSubset(t, result, left, right)
	assertUnionHandledCoversCommon(t, result, left, right)
	assertUnionScopedSubset(t, result, left, right)
	assertUnionScopedCoversCommon(t, result, left, right)
}

func assertUnionPathCoverage(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPaths := make(map[string]struct{})
	for _, rule := range result.PathRules {
		resultPaths[rule.Path] = struct{}{}
	}

	handled := fsRightSet(result.HandledAccessFS)

	// Rights outside the merged handled set are pruned, so a rule survives
	// only when it grants a handled right.
	for _, input := range []*landlock.Profile{left, right} {
		for _, rule := range input.PathRules {
			if _, ok := resultPaths[rule.Path]; !ok &&
				len(handledFSRights(rule.AccessFS, handled)) > 0 {
				t.Errorf("path %q missing from union", rule.Path)
			}
		}
	}

	if !slices.IsSortedFunc(
		result.PathRules,
		func(a, b landlock.PathRule) int {
			return cmp.Compare(a.Path, b.Path)
		},
	) {
		t.Error("result path rules are not sorted")
	}
}

func assertUnionHandledSubset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	leftHandledFS := fsRightSet(left.HandledAccessFS)
	rightHandledFS := fsRightSet(right.HandledAccessFS)

	for _, r := range result.HandledAccessFS {
		_, inL := leftHandledFS[r]
		_, inR := rightHandledFS[r]

		if !inL || !inR {
			t.Errorf("union handled FS right %q not in both inputs", r)
		}
	}

	leftHandledNet := netRightSet(left.HandledAccessNet)
	rightHandledNet := netRightSet(right.HandledAccessNet)

	for _, r := range result.HandledAccessNet {
		_, inL := leftHandledNet[r]
		_, inR := rightHandledNet[r]

		if !inL || !inR {
			t.Errorf("union handled Net right %q not in both inputs", r)
		}
	}
}

func assertUnionHandledCoversCommon(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	assertUnionHandledCoversCommonFS(t, result, left, right)
	assertUnionHandledCoversCommonNet(t, result, left, right)
}

func assertUnionHandledCoversCommonFS(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultFS := fsRightSet(result.HandledAccessFS)
	rightFS := fsRightSet(right.HandledAccessFS)

	for _, fsRight := range left.HandledAccessFS {
		if _, inR := rightFS[fsRight]; !inR {
			continue
		}

		if _, ok := resultFS[fsRight]; !ok {
			t.Errorf("union handled FS missing common right %q", fsRight)
		}
	}
}

func assertUnionHandledCoversCommonNet(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultNet := netRightSet(result.HandledAccessNet)
	rightNet := netRightSet(right.HandledAccessNet)

	for _, netRight := range left.HandledAccessNet {
		if _, inR := rightNet[netRight]; !inR {
			continue
		}

		if _, ok := resultNet[netRight]; !ok {
			t.Errorf("union handled Net missing common right %q", netRight)
		}
	}
}

func assertUnionPathRightsSuperset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPaths := pathRuleMap(result.PathRules)
	leftPaths := pathRuleMap(left.PathRules)
	rightPaths := pathRuleMap(right.PathRules)

	handled := fsRightSet(result.HandledAccessFS)

	assertPathRightsPresent(t, leftPaths, rightPaths, resultPaths, handled)
	assertPathRightsPresent(t, rightPaths, leftPaths, resultPaths, handled)
}

func assertPathRightsPresent(
	t *testing.T,
	source, other map[string][]landlock.FSAccessRight,
	result map[string][]landlock.FSAccessRight,
	handled map[landlock.FSAccessRight]struct{},
) {
	t.Helper()

	for path, access := range source {
		if _, inOther := other[path]; !inOther {
			continue
		}

		expected := handledFSRights(access, handled)
		if len(expected) == 0 {
			continue
		}

		resultAccess, inResult := result[path]
		if !inResult {
			t.Errorf("union missing shared path %q", path)

			continue
		}

		resultSet := fsRightSet(resultAccess)

		for _, right := range expected {
			if _, ok := resultSet[right]; !ok {
				t.Errorf("union path %q missing right %q", path, right)
			}
		}
	}
}

// handledFSRights returns the rights of access that are in handled.
func handledFSRights(
	access []landlock.FSAccessRight, handled map[landlock.FSAccessRight]struct{},
) []landlock.FSAccessRight {
	var kept []landlock.FSAccessRight

	for _, right := range access {
		if _, ok := handled[right]; ok {
			kept = append(kept, right)
		}
	}

	return kept
}

func assertUnionNetRightsSuperset(
	t *testing.T,
	result, left, right *landlock.Profile,
) {
	t.Helper()

	resultPorts := netRulePortMap(result.NetRules)
	leftPorts := netRulePortMap(left.NetRules)
	rightPorts := netRulePortMap(right.NetRules)

	handled := netRightSet(result.HandledAccessNet)

	assertNetRightsPresent(t, leftPorts, rightPorts, resultPorts, handled)
	assertNetRightsPresent(t, rightPorts, leftPorts, resultPorts, handled)
}

func assertNetRightsPresent(
	t *testing.T,
	source, other map[uint16][]landlock.NetAccessRight,
	result map[uint16][]landlock.NetAccessRight,
	handled map[landlock.NetAccessRight]struct{},
) {
	t.Helper()

	for port, access := range source {
		if _, inOther := other[port]; !inOther {
			continue
		}

		var expected []landlock.NetAccessRight

		for _, right := range access {
			if _, ok := handled[right]; ok {
				expected = append(expected, right)
			}
		}

		if len(expected) == 0 {
			continue
		}

		resultAccess, inResult := result[port]
		if !inResult {
			t.Errorf("union missing shared port %d", port)

			continue
		}

		resultSet := netRightSet(resultAccess)

		for _, right := range expected {
			if _, ok := resultSet[right]; !ok {
				t.Errorf("union port %d missing right %q", port, right)
			}
		}
	}
}

func profilesEqual(a, b *landlock.Profile) bool {
	return slices.Equal(a.HandledAccessFS, b.HandledAccessFS) &&
		slices.Equal(a.HandledAccessNet, b.HandledAccessNet) &&
		slices.Equal(a.Scoped, b.Scoped) &&
		pathRulesEqual(a.PathRules, b.PathRules) &&
		netRulesEqual(a.NetRules, b.NetRules)
}

func pathRulesEqual(left, right []landlock.PathRule) bool {
	if len(left) != len(right) {
		return false
	}

	for idx := range left {
		if left[idx].Path != right[idx].Path {
			return false
		}

		if !slices.Equal(left[idx].AccessFS, right[idx].AccessFS) {
			return false
		}
	}

	return true
}

func netRulesEqual(left, right []landlock.NetRule) bool {
	if len(left) != len(right) {
		return false
	}

	for idx := range left {
		if left[idx].Port != right[idx].Port {
			return false
		}

		if !slices.Equal(left[idx].AccessNet, right[idx].AccessNet) {
			return false
		}
	}

	return true
}

func FuzzLandlockIntersect(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Intersect,
		checkInv: assertIntersectInvariants,
		equal:    semanticallyEqual,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8, scopeL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8, scopeR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		fuzzMerge(t, cfg,
			hfsL, hnetL, scopeL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
			hfsR, hnetR, scopeR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)
	})
}

func FuzzLandlockUnion(f *testing.F) {
	addLandlockFuzzSeeds(f)

	cfg := fuzzMergeConfig{
		merge:    landlock.Union,
		checkInv: assertUnionInvariants,
		equal:    profilesEqual,
	}

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8, scopeL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8, scopeR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		fuzzMerge(t, cfg,
			hfsL, hnetL, scopeL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
			hfsR, hnetR, scopeR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)
	})
}

func FuzzLandlockDiff(f *testing.F) {
	addLandlockFuzzSeeds(f)

	f.Fuzz(func(
		t *testing.T,
		hfsL uint32, hnetL uint8, scopeL uint8,
		p1L, p2L string,
		am1L, am2L uint32,
		port1L, port2L uint16,
		nm1L, nm2L uint8,
		hfsR uint32, hnetR uint8, scopeR uint8,
		p1R, p2R string,
		am1R, am2R uint32,
		port1R, port2R uint16,
		nm1R, nm2R uint8,
	) {
		left := fuzzLandlockProfile(
			hfsL, hnetL, scopeL, p1L, p2L,
			am1L, am2L, port1L, port2L, nm1L, nm2L,
		)
		right := fuzzLandlockProfile(
			hfsR, hnetR, scopeR, p1R, p2R,
			am1R, am2R, port1R, port2R, nm1R, nm2R,
		)

		diff, err := landlock.Diff(left, right)
		if err != nil {
			t.Fatal(err)
		}

		landlock.FormatDiff(diff)

		reverse, err := landlock.Diff(right, left)
		if err != nil {
			t.Fatal(err)
		}

		if diff.Equal != reverse.Equal {
			t.Error("Diff(L,R).Equal != Diff(R,L).Equal")
		}

		assertRightsDiffSwapped(t, "HandledAccessFS", diff.HandledAccessFS, reverse.HandledAccessFS)
		assertRightsDiffSwapped(
			t,
			"HandledAccessNet",
			diff.HandledAccessNet,
			reverse.HandledAccessNet,
		)
		assertRightsDiffSwapped(t, "Scoped", diff.Scoped, reverse.Scoped)
		assertRulesDiffSwapped(t, "PathRules", diff.PathRules, reverse.PathRules)
		assertNetRulesDiffSwapped(t, diff.NetRules, reverse.NetRules)

		selfDiff, err := landlock.Diff(left, left)
		if err != nil {
			t.Fatal(err)
		}

		if !selfDiff.Equal {
			t.Error("Diff(X, X) must be equal")
		}
	})
}

func FuzzLandlockValidateStrict(f *testing.F) {
	f.Add(
		uint32(0x07), uint8(0x03), uint8(0x03), "/etc", "/home",
		uint32(0x05), uint32(0x03), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x03), uint8(0x01), uint8(0x02), "/etc", "/home",
		uint32(0x01), uint32(0x02), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x00), "/a", "/b",
		uint32(0x01), uint32(0x02), uint16(80), uint16(443),
		uint8(0x01), uint8(0x02),
	)
	f.Add(
		uint32(0x3FFFF), uint8(0x3F), uint8(0x03), "/etc", "/home",
		uint32(0x00), uint32(0x00), uint16(80), uint16(443),
		uint8(0x00), uint8(0x00),
	)

	f.Fuzz(func(
		_ *testing.T,
		hfs uint32, hnet uint8, scope uint8,
		path1, path2 string,
		am1, am2 uint32,
		port1, port2 uint16,
		nm1, nm2 uint8,
	) {
		profile := fuzzLandlockProfile(
			hfs, hnet, scope, path1, path2,
			am1, am2, port1, port2, nm1, nm2,
		)

		_ = landlock.ValidateStrict(profile)
	})
}

func assertRightsDiffSwapped[T comparable](
	t *testing.T, label string,
	fwd, rev *landlock.RightsDiff[T],
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if !slices.Equal(fwd.Added, rev.Removed) {
		t.Errorf("%s: forward Added != reverse Removed", label)
	}

	if !slices.Equal(fwd.Removed, rev.Added) {
		t.Errorf("%s: forward Removed != reverse Added", label)
	}
}

func assertRulesDiffSwapped(
	t *testing.T, label string,
	fwd, rev *landlock.PathRulesDiff,
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Errorf("%s: nil mismatch", label)

		return
	}

	if fwd == nil {
		return
	}

	if len(fwd.Added) != len(rev.Removed) {
		t.Errorf(
			"%s: forward Added count %d != reverse Removed count %d",
			label, len(fwd.Added), len(rev.Removed),
		)
	}

	if len(fwd.Removed) != len(rev.Added) {
		t.Errorf(
			"%s: forward Removed count %d != reverse Added count %d",
			label, len(fwd.Removed), len(rev.Added),
		)
	}
}

func assertNetRulesDiffSwapped(
	t *testing.T,
	fwd, rev *landlock.NetRulesDiff,
) {
	t.Helper()

	if (fwd == nil) != (rev == nil) {
		t.Error("NetRules: nil mismatch")

		return
	}

	if fwd == nil {
		return
	}

	if len(fwd.Added) != len(rev.Removed) {
		t.Errorf(
			"NetRules: forward Added count %d != reverse Removed count %d",
			len(fwd.Added), len(rev.Removed),
		)
	}

	if len(fwd.Removed) != len(rev.Added) {
		t.Errorf(
			"NetRules: forward Removed count %d != reverse Added count %d",
			len(fwd.Removed), len(rev.Added),
		)
	}
}
