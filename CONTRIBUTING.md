# Contributing Guidelines

Welcome to Kubernetes. We are excited about the prospect of you joining our
[community](https://git.k8s.io/community)! The Kubernetes community abides by
the CNCF [code of conduct](code-of-conduct.md). Here is an excerpt:

_As contributors and maintainers of this project, and in the interest of
fostering an open and welcoming community, we pledge to respect all people who
contribute through reporting issues, posting feature requests, updating
documentation, submitting pull requests or patches, and other activities._

## Getting Started

We have full documentation on how to get started contributing here:

- [Contributor License Agreement](https://git.k8s.io/community/CLA.md) -
  Kubernetes projects require that you sign a Contributor License Agreement
  (CLA) before we can accept your pull requests
- [Kubernetes Contributor Guide](https://k8s.dev/guide) - Main contributor
  documentation, or you can just jump directly to the
  [contributing page](https://k8s.dev/docs/guide/contributing/)
- [Contributor Cheat Sheet](https://k8s.dev/cheatsheet) - Common resources for
  existing developers

## Architecture

The codebase is organized in three layers:

- `internal/merge/` contains generic merge primitives (`Fold`, `IntersectSlice`,
  `UnionSlice`, `DiffSlice`) that work with any comparable type. All profile
  packages build on these primitives.
- `seccomp/`, `apparmor/`, `landlock/` each expose the same public API surface:
  `Intersect`, `Union`, `Validate`, `ValidateStrict`, `Diff`, `FormatDiff`, and
  `FormatProfile` (seccomp additionally exposes `ValidateArtifact` for
  untrusted OCI artifact input). Each package defines its own types (seccomp uses OCI
  runtime-spec types, apparmor and landlock define their own) and implements
  profile-specific normalization, deduplication, and merge logic on top of
  `internal/merge/`. The seccomp package merges syscalls through a clause
  model (`rules.go`, `args.go`) that reasons about argument filter regions.
- `cmd/spm/` is a thin CLI layer that wires the packages together using Go
  generics. It uses the standard library `flag` package with manual subcommand
  dispatch.

## Local Development

```sh
make                     # build, lint, and test (default target)
make help                # display available targets
make build               # build the spm binary (static)
make test                # run tests with race detection and coverage
make lint                # run golangci-lint
make fuzz                # run all fuzz tests (default 30s, set FUZZTIME to adjust)
make bench               # run benchmarks
make verify-coverage     # verify test coverage meets threshold (default 90%)
make verify-tidy         # verify go.mod is tidy
make verify-mdtoc        # verify table of contents in markdown files
make verify-dependencies # verify external dependencies
make govulncheck         # run govulncheck
make tidy                # run go mod tidy
make clean               # remove build artifacts
```

## Mentorship

- [Mentoring Initiatives](https://k8s.dev/community/mentoring) - We have a
  diverse set of mentorship programs available that are always looking for
  volunteers!
