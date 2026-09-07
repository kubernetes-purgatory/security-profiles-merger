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

package seccomp

import (
	"cmp"
	"maps"
	"slices"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/saschagrunert/security-profiles-merger/internal/merge"
)

// clause is a single rule for one syscall: an action, an optional errno, and
// optional argument filters. A clause without args is unconditional.
//
// The evaluation model for one syscall within a profile is:
//   - if any conditional clause matches the call, the least restrictive
//     action among the matching conditional clauses applies;
//   - otherwise the unconditional clause applies if present;
//   - otherwise the profile default applies.
//
// Conditional clauses therefore take precedence over an unconditional clause
// for the same syscall. Duplicate unconditional clauses resolve to the least
// restrictive action.
type clause struct {
	action   specs.LinuxSeccompAction
	errnoRet *uint
	args     []specs.LinuxSeccompArg
}

func (c clause) unconditional() bool { return len(c.args) == 0 }

// sameResult reports whether two clauses yield the same runtime effect,
// ignoring their argument filters.
func (c clause) sameResult(other clause) bool {
	return actionsEquivalent(c.action, other.action) &&
		equalUintPtr(c.errnoRet, other.errnoRet)
}

// pickClause selects between two clauses using the given action preference.
// On a tie the left clause wins, so ErrnoRet comes from the leftmost profile.
func pickClause(
	left, right clause,
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction,
) clause {
	if actionsEquivalent(left.action, right.action) {
		return left
	}

	if actionsEquivalent(pick(left.action, right.action), left.action) {
		return left
	}

	return right
}

func lessRestrictiveClause(left, right clause) clause {
	return pickClause(left, right, LessRestrictive)
}

// syscallRules holds every clause of one profile for a single syscall name.
type syscallRules struct {
	unconditional *clause
	conditional   []clause
}

// collectRules splits syscall entries into per-name clause sets. Multi-name
// entries contribute one clause per name. Duplicate unconditional entries
// resolve to the least restrictive action.
func collectRules(syscalls []specs.LinuxSyscall) map[string]*syscallRules {
	rules := make(map[string]*syscallRules)

	for idx := range syscalls {
		entry := &syscalls[idx]

		for _, name := range entry.Names {
			current, ok := rules[name]
			if !ok {
				current = &syscallRules{unconditional: nil, conditional: nil}
				rules[name] = current
			}

			next := clause{
				action:   entry.Action,
				errnoRet: merge.ClonePtr(entry.ErrnoRet),
				args:     sortedArgs(entry.Args),
			}

			if !next.unconditional() {
				current.conditional = append(current.conditional, next)

				continue
			}

			if current.unconditional == nil {
				current.unconditional = &next
			} else {
				picked := lessRestrictiveClause(*current.unconditional, next)
				current.unconditional = &picked
			}
		}
	}

	return rules
}

// fallback returns the clause applied when no conditional clause matches:
// the unconditional clause if present, otherwise the given profile default.
// A nil default (bare syscall lists) yields nil when no unconditional clause
// exists.
func (r *syscallRules) fallback(def *clause) *clause {
	if r != nil && r.unconditional != nil {
		return r.unconditional
	}

	return def
}

func (r *syscallRules) conditionals() []clause {
	if r == nil {
		return nil
	}

	return r.conditional
}

// ruleMerger describes one merge direction over the clause model.
type ruleMerger struct {
	// pick chooses the action for a call that both sides constrain.
	pick func(first, second specs.LinuxSeccompAction) specs.LinuxSeccompAction
	// intersect selects intersection semantics: a fallback exists only when
	// both sides have one, unconstrained regions are dropped, and a clause is
	// emitted for the overlap of two conditional clauses to express "both
	// filters hold". Union keeps every input clause instead.
	intersect bool
}

func intersectRules() ruleMerger {
	return ruleMerger{pick: MoreRestrictive, intersect: true}
}

func unionRules() ruleMerger {
	return ruleMerger{pick: LessRestrictive, intersect: false}
}

func (m ruleMerger) pickClause(left, right clause) clause {
	return pickClause(left, right, m.pick)
}

// mergeRules merges the clauses of one syscall from two sides.
//
// For intersection the result never permits more than either input, and for
// union it never permits less, under the evaluation model documented on the
// clause type. Where the exact result is not expressible, intersection
// falls back to the more restrictive and union to the less restrictive
// surrounding action.
//
// leftDef and rightDef are the profile defaults, or nil for bare syscall
// lists. The returned fallback is the unconditional clause of the result, or
// nil when only the caller's default applies.
func (m ruleMerger) mergeRules(
	left, right *syscallRules,
	leftDef, rightDef *clause,
) (*clause, []clause) {
	leftFallback := left.fallback(leftDef)
	rightFallback := right.fallback(rightDef)
	fallback := m.mergeFallback(leftFallback, rightFallback)

	leftConds := left.conditionals()
	rightConds := right.conditionals()

	var conditional []clause

	conditional = append(conditional, m.adjustClauses(leftConds, rightConds, rightFallback)...)
	conditional = append(conditional, m.adjustClauses(rightConds, leftConds, leftFallback)...)

	if m.intersect {
		for _, leftClause := range leftConds {
			for _, rightClause := range rightConds {
				args, ok := conjoinClauseArgs(leftClause.args, rightClause.args)
				if !ok {
					continue
				}

				picked := m.pickClause(leftClause, rightClause)
				picked.args = args
				conditional = append(conditional, picked)
			}
		}
	}

	return fallback, collapseClauses(conditional, fallback)
}

// mergeFallback combines the fallback clauses of both sides. Intersection
// needs both to be present; union takes whichever exists.
func (m ruleMerger) mergeFallback(left, right *clause) *clause {
	switch {
	case left != nil && right != nil:
		picked := m.pickClause(*left, *right)

		return &picked
	case m.intersect:
		return nil
	case left != nil:
		return left
	default:
		return right
	}
}

// adjustClauses returns one clause per entry of clauses, with the action
// combined against what the other side may apply inside the clause's
// argument region. For intersection this lowers the action to what both
// sides allow; for union it raises it to what either side allows.
//
// The other side's fallback applies inside the region unless an other-side
// clause matches everything the clause matches (its filter is a subset), in
// which case the fallback can never be reached there. Intersection also
// lowers the action by every overlapping other-side clause, because the
// result is evaluated as the least restrictive matching clause. Union does
// not need that: every other-side clause is emitted on its own and raises
// the result wherever it matches.
//
// When the other side has no fallback (bare lists) and no overlapping
// clause, the region is unconstrained on that side: intersection drops the
// clause and union keeps it unchanged.
func (m ruleMerger) adjustClauses(
	clauses, others []clause, otherFallback *clause,
) []clause {
	result := make([]clause, 0, len(clauses))

	for _, current := range clauses {
		adjusted, overlapping, subsumed := m.adjustAgainstOthers(current, others)

		if otherFallback != nil && !subsumed {
			adjusted = m.pickClause(adjusted, *otherFallback)
		}

		if m.intersect && otherFallback == nil && !overlapping {
			continue
		}

		adjusted.args = current.args
		result = append(result, adjusted)
	}

	return result
}

// adjustAgainstOthers combines current with every overlapping other-side
// clause (intersection only) and reports whether any other-side clause
// overlaps current and whether one subsumes it.
func (m ruleMerger) adjustAgainstOthers(
	current clause, others []clause,
) (clause, bool, bool) {
	adjusted := current
	overlapping := false
	subsumed := false

	for _, other := range others {
		if argsDisjoint(current.args, other.args) {
			continue
		}

		overlapping = true

		if argsSubset(other.args, current.args) {
			subsumed = true
		}

		if m.intersect {
			adjusted = m.pickClause(adjusted, other)
		}
	}

	return adjusted, overlapping, subsumed
}

// conjoinClauseArgs returns the filter matching the overlap of two
// conditional clauses. Identical filters are kept as-is; otherwise the
// filters must not be provably disjoint and must be conjoinable.
func conjoinClauseArgs(
	left, right []specs.LinuxSeccompArg,
) ([]specs.LinuxSeccompArg, bool) {
	if argsKey(left) == argsKey(right) {
		return slices.Clone(left), true
	}

	if argsDisjoint(left, right) {
		return nil, false
	}

	return conjoinArgs(left, right)
}

// collapseClauses merges clauses with identical argument filters (keeping the
// least restrictive, since they always match together) and drops clauses
// that yield the same result as the fallback. A clause equal to the fallback
// is still kept when a stricter clause may overlap it: removing it would let
// the stricter clause win where both matched.
func collapseClauses(clauses []clause, fallback *clause) []clause {
	byArgs := make(map[string]clause, len(clauses))
	order := make([]string, 0, len(clauses))

	for _, current := range clauses {
		key := argsKey(current.args)

		existing, ok := byArgs[key]
		if !ok {
			byArgs[key] = current
			order = append(order, key)

			continue
		}

		byArgs[key] = lessRestrictiveClause(existing, current)
	}

	result := make([]clause, 0, len(order))

	for _, key := range order {
		current := byArgs[key]
		if fallback != nil && current.sameResult(*fallback) &&
			!overlapsStricter(current, key, byArgs) {
			continue
		}

		result = append(result, current)
	}

	slices.SortFunc(result, func(a, b clause) int {
		return cmp.Compare(argsKey(a.args), argsKey(b.args))
	})

	return result
}

// overlapsStricter reports whether any other clause may match a call that
// current matches while applying a strictly more restrictive action.
func overlapsStricter(current clause, key string, byArgs map[string]clause) bool {
	for otherKey, other := range byArgs {
		if otherKey == key || argsDisjoint(current.args, other.args) {
			continue
		}

		if !actionsEquivalent(other.action, current.action) &&
			actionsEquivalent(MoreRestrictive(other.action, current.action), other.action) {
			return true
		}
	}

	return false
}

func defaultClause(profile *specs.LinuxSeccomp) *clause {
	return &clause{
		action:   profile.DefaultAction,
		errnoRet: merge.ClonePtr(profile.DefaultErrnoRet),
		args:     nil,
	}
}

// mergeProfileSyscalls merges the syscall entries of two profiles given the
// merged default clause. Entries equal to the merged default are elided.
func (m ruleMerger) mergeProfileSyscalls(
	left, right *specs.LinuxSeccomp,
	mergedDefault *clause,
) []specs.LinuxSyscall {
	leftRules := collectRules(left.Syscalls)
	rightRules := collectRules(right.Syscalls)
	leftDef := defaultClause(left)
	rightDef := defaultClause(right)

	names := slices.Sorted(maps.Keys(leftRules))

	for name := range rightRules {
		if _, ok := leftRules[name]; !ok {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	var result []specs.LinuxSyscall

	for _, name := range names {
		fallback, conditional := m.mergeRules(
			leftRules[name], rightRules[name], leftDef, rightDef,
		)

		if fallback != nil && !fallback.sameResult(*mergedDefault) {
			result = append(result, clauseToSyscall(name, *fallback))
		}

		for _, current := range conditional {
			result = append(result, clauseToSyscall(name, current))
		}
	}

	return result
}

// mergeBareSyscalls merges two syscall lists that carry no profile default.
// Names present on one side only are dropped for intersection and kept for
// union.
func (m ruleMerger) mergeBareSyscalls(left, right []specs.LinuxSyscall) []specs.LinuxSyscall {
	leftRules := collectRules(left)
	rightRules := collectRules(right)

	names := slices.Sorted(maps.Keys(leftRules))

	if !m.intersect {
		for name := range rightRules {
			if _, ok := leftRules[name]; !ok {
				names = append(names, name)
			}
		}
	}

	var result []specs.LinuxSyscall

	for _, name := range names {
		leftRule, inLeft := leftRules[name]
		rightRule, inRight := rightRules[name]

		if m.intersect && (!inLeft || !inRight) {
			continue
		}

		fallback, conditional := m.mergeRules(leftRule, rightRule, nil, nil)
		if fallback != nil {
			result = append(result, clauseToSyscall(name, *fallback))
		}

		for _, current := range conditional {
			result = append(result, clauseToSyscall(name, current))
		}
	}

	return result
}

func clauseToSyscall(name string, current clause) specs.LinuxSyscall {
	return specs.LinuxSyscall{
		Names:    []string{name},
		Action:   current.action,
		ErrnoRet: merge.ClonePtr(current.errnoRet),
		Args:     slices.Clone(current.args),
	}
}
