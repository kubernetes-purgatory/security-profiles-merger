# API Reference

<!-- toc -->
- [seccomp](#seccomp)
  - [Functions](#functions)
  - [Types](#types)
  - [Errors](#errors)
  - [Merge semantics](#merge-semantics)
- [apparmor](#apparmor)
  - [Functions](#functions-1)
  - [Types](#types-1)
  - [Errors](#errors-1)
  - [Glob patterns](#glob-patterns)
  - [Nil vs empty semantics](#nil-vs-empty-semantics)
  - [Filesystem merge](#filesystem-merge)
- [landlock](#landlock)
  - [Functions](#functions-2)
  - [Types](#types-2)
  - [Errors](#errors-2)
  - [Handled access semantics](#handled-access-semantics)
  - [IPC scoping](#ipc-scoping)
  - [Path and network rules](#path-and-network-rules)
<!-- /toc -->

For full Go documentation, see the
[pkg.go.dev reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger).

## seccomp

Seccomp profile merge operating on `specs.LinuxSeccomp` from the
[OCI runtime-spec](https://github.com/opencontainers/runtime-spec).

```go
import "github.com/saschagrunert/security-profiles-merger/seccomp"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge profiles via intersection (most restrictive wins) |
| `Union` | Merge profiles via union (least restrictive wins) |
| `IntersectSyscalls` | Intersect two bare syscall slices without a DefaultAction |
| `UnionSyscalls` | Union two bare syscall slices without a DefaultAction |
| `DiffSyscalls` | Diff two bare syscall slices, returning added/removed/changed |
| `MoreRestrictive` | Return the more restrictive of two seccomp actions |
| `LessRestrictive` | Return the less restrictive of two seccomp actions |
| `Validate` | Check for known actions and non-empty syscall names |
| `ValidateStrict` | All Validate checks plus duplicates, unknown archs/flags/operators |
| `FormatProfile` | Human-readable representation of a seccomp profile |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/seccomp)
for full signatures and documentation.

### Types

Diff types (`ProfileDiff`, `ActionDiff`, `UintPtrDiff`, `StringDiff`,
`SliceDiff`, `SyscallsDiff`, `SyscallEntry`, `SyscallChange`, `SyscallDetail`)
are documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/seccomp#ProfileDiff).

`SyscallEntry` and `SyscallDetail` implement `fmt.Stringer` for human-readable
formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrUnknownAction`,
`ErrEmptySyscallNames`, `ErrDuplicateSyscallName`, `ErrUnknownOperator`,
`ErrArgIndexOutOfRange`, `ErrUnknownArch`, `ErrUnknownFlag`, etc.) are documented
in the [package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/seccomp#pkg-variables).

### Merge semantics

- Default actions are merged using the same restrictiveness comparison as
  syscalls.
- Architectures: intersection keeps only architectures present in all profiles;
  union combines all. An empty architecture list is treated as "unspecified" and
  defers to the other profile. Per the OCI runtime-spec, empty means "native
  architecture only", but the native architecture is unknown at merge time.
  Callers that need precise architecture intersection should populate the native
  architecture explicitly before merging.
- Flags: intersection keeps only flags present in all profiles; union combines
  all. An empty flag list means "no flags", so intersecting with it yields no
  flags. This keeps an OCI-pulled profile from enabling
  `SECCOMP_FILTER_FLAG_SPEC_ALLOW` over a baseline that did not set it.
- Evaluation model: entries are evaluated the way runc and libseccomp load
  them. Entries whose action (and errno, for `ERRNO` and `TRACE`) equals the
  profile default are ignored. An unconditional entry applies to every call of
  its syscall and overrides conditional entries for the same syscall, because
  libseccomp drops conditional rules once an unconditional rule exists; when
  several unconditional entries exist, the first one wins. Otherwise a
  conditional entry applies to calls matching all of its filters, and if
  several conditional entries match, the least restrictive action applies. If
  none matches, the profile default applies. Multiple entries for the same
  syscall (an OR of filters) are preserved. An entry with several conditions
  on the same argument index is loaded by runc as one rule per condition, so
  it is treated as alternatives rather than a conjunction.
- Merge results never carry an unconditional entry next to conditional
  entries for the same syscall, since the runtime would discard the
  conditional ones. Where the merged rules would need both, a single filter
  is rewritten as the filter plus its complement (for example `arg0 == 1` and
  `arg0 != 1`), which is exact; anything else collapses to one unconditional
  entry with the more restrictive (intersection) or less restrictive (union)
  action.
- Argument filters during intersection: for each call, the more restrictive
  action of the two profiles is chosen. Filters on different argument indices
  are conjoined into one entry, identical filters are kept, and filters that
  provably never overlap (for example `arg0 == 1` and `arg0 == 2`) produce no
  shared entry. Where the exact intersection is not expressible in OCI terms,
  such as different conditions on the same argument index, the affected calls
  fall back to the more restrictive surrounding action. The result never
  permits a call that any input denies.
- Argument filters during union: every conditional entry of every input is
  kept, with its action raised to the least restrictive action any input
  applies to matching calls. The result never denies a call that any input
  permits.
- Output grouping: entries sharing the same action, errno, and argument filters
  are emitted as one multi-name entry, sorted by name.
- `DefaultErrnoRet` is taken from whichever profile's default action is selected.
  When both profiles share the same action, the earlier (leftmost) profile's
  `DefaultErrnoRet` wins. The same applies to per-syscall `ErrnoRet`. `ErrnoRet`
  is only significant for `ERRNO` and `TRACE`; on other actions it is ignored
  when comparing entries. Because of the leftmost rule, whether a conditional
  entry that shares the default action but not its errno survives can depend
  on argument order, so results are order-independent in effect only for
  profiles without errno values.
- `ListenerPath` and `ListenerMetadata` are taken from the first profile.

**Action restrictiveness ordering** (most to least restrictive):

`KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > NOTIFY > TRACE > LOG > ALLOW`

`MoreRestrictive` and `LessRestrictive` treat unknown actions as maximally
restrictive. `Intersect` and `Union` validate their inputs first and reject
unknown actions with `ErrUnknownAction`.

## apparmor

AppArmor profile merge using structured profile types defined in this package.

```go
import "github.com/saschagrunert/security-profiles-merger/apparmor"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection; capabilities/paths intersected, network AND |
| `Union` | Merge via union; all rules combined, network OR |
| `Validate` | Check for cross-category path conflicts and known capabilities |
| `ValidateStrict` | All Validate checks plus duplicate executables/libraries |
| `FormatProfile` | Human-readable representation of an AppArmor profile |
| `IsGlobPattern` | Report whether a path contains AppArmor glob tokens |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/apparmor)
for full signatures and documentation.

### Types

Core types (`Profile`, `CapabilityRules`, `ExecutableRules`, `FilesystemRules`,
`NetworkRules`, `AllowedProtocols`) and diff types (`ProfileDiff`,
`StringSliceDiff`, `FilesystemDiff`, `NetworkDiff`, `BoolPtrDiff`) are
documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/apparmor#Profile).

`Profile`, `ExecutableRules`, `FilesystemRules`, `NetworkRules`, and
`CapabilityRules` implement `fmt.Stringer` for human-readable formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrDuplicatePath`,
`ErrUnknownCapability`, `ErrDuplicateExecutablePath`, etc.) are documented
in the [package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/apparmor#pkg-variables).

### Glob patterns

Paths may use AppArmor glob syntax: `*` (any characters except `/`), `**`
(any characters including `/`), `?` (one character except `/`), character
classes such as `[abc]`, `[a-z]`, and `[^a]`, and alternations such as
`{a,b}`, which may nest and may contain further glob tokens. As in the
AppArmor parser, `*` and `**` at the start of a path component match at least
one character, so `/dir/**` does not match `/dir/` itself. A backslash escapes
the following character, and an escaped literal such as `/etc/\*` is matched
against globs as the file name `/etc/*`. Literal paths are cleaned but keep a
trailing slash, which distinguishes a directory rule from a file rule. On
intersection a literal path survives when a glob on the other side matches
it, and two globs survive only when they are identical or one is the `**`
expansion of a literal prefix containing the other's prefix (so `/etc/**`
narrows to `/etc/*.conf` and to `/etc/foo/*.conf`). On union a glob prunes
literals it matches; globs never prune other globs. Patterns longer than 4096
bytes or with more than 100 alternatives in total never match, so they are
dropped on intersection and kept verbatim on union.

### Nil vs empty semantics

A nil field means "unspecified" and defers to the other profile during merge. A
non-nil field with empty contents means "explicitly no permissions". For example,
intersecting `{caps: [NET_ADMIN]}` with `{caps: nil}` yields `[NET_ADMIN]`,
while intersecting with `{caps: []}` yields `[]`.

### Filesystem merge

Paths are expanded into read/write permission pairs, merged per path (AND for
intersection, OR for union), and collapsed back into read-only, write-only, and
read-write lists. A read-write path intersected with a read-only path becomes
read-only (only the shared permission survives). A read-only path in one profile
and write-only in the other is dropped on intersection (no shared permissions)
but becomes read-write on union. When two non-nil filesystem rule sets produce
no overlapping paths after intersection, the result is a non-nil empty
`FilesystemRules` (preserving the nil-vs-empty distinction).

## landlock

Landlock profile merge for Linux unprivileged sandboxing rulesets.

```go
import "github.com/saschagrunert/security-profiles-merger/landlock"
```

### Functions

| Function | Description |
|----------|-------------|
| `Intersect` | Merge via intersection; handled sets unioned, rules intersected |
| `Union` | Merge via union; handled sets intersected, rules unioned |
| `Validate` | Check for known rights, valid paths, and duplicate rules |
| `ValidateStrict` | All Validate checks plus unhandled-right and relative path detection |
| `FormatProfile` | Human-readable representation of a Landlock profile |
| `Diff` | Structured diff between two profiles |
| `FormatDiff` | Human-readable representation of a profile diff |

See [pkg.go.dev](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/landlock)
for full signatures and documentation.

### Types

Core types (`Profile`, `FSAccessRight`, `NetAccessRight`, `ScopeRight`,
`PathRule`, `NetRule`) and diff types (`ProfileDiff`, `RightsDiff`,
`PathRulesDiff`, `PathRuleChange`, `NetRulesDiff`, `NetRuleChange`) are
documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/landlock#Profile).

`Profile`, `PathRule`, and `NetRule` implement `fmt.Stringer` for human-readable
formatting.

### Errors

Sentinel errors (`ErrNoProfiles`, `ErrNilProfile`, `ErrUnknownRight`,
`ErrDuplicateRule`, `ErrEmptyPath`, `ErrInvalidPath`, `ErrUnhandledRight`,
`ErrDuplicateRight`, `ErrRelativePath`, etc.) are documented in the
[package reference](https://pkg.go.dev/github.com/saschagrunert/security-profiles-merger/landlock#pkg-variables).

### Handled access semantics

Landlock has inverted merge semantics for handled-access sets and scope
restrictions compared to rules. Unhandled access rights are implicitly allowed,
so intersection unions the handled sets and scoped sets (handling more rights /
scoping more makes the ruleset more restrictive), and union intersects them
(handling fewer rights / scoping less makes it less restrictive).

### IPC scoping

Scope restrictions (abstract_unix_socket, signal) have no exceptions via rules.
Once scoped, access outside the Landlock domain is fully blocked. During merge,
scoped sets follow the same inverted semantics as handled access sets.

### Path and network rules

During intersection, a right is granted for a path or port only if every
profile permits it there. A profile permits a right if it does not handle the
right (unhandled rights are implicitly allowed) or if one of its rules grants
it. Path rules cover the whole hierarchy beneath their path and rights from
nested rules accumulate, so a rule on `/etc` in one profile intersected with a
rule on `/` in the other yields a rule on `/etc`. Network rules match by exact
port. During union, access rights are combined for matching entries, and all
non-matching entries are kept.

Rights outside the merged handled sets are pruned from rules, and rules left
without rights are dropped. Unhandled rights are implicitly allowed, so this
does not change what the result permits, but the kernel rejects a rule whose
rights are not a subset of the handled access set. Merge results therefore
pass `ValidateStrict` when the inputs use absolute paths.

Paths are cleaned before merging and before duplicate detection in
`Validate`, so `/etc` and `/etc/` are the same rule. Empty paths, paths that
clean to `.`, and paths containing NUL bytes are rejected. Intersect and Union
deduplicate rules and rights within each input before validating it, so
duplicates within one input are merged rather than rejected there.
