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

// Package main implements the spm CLI for merging and validating security profiles.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var version = "dev"

const (
	exitUsage = 2

	cmdMerge    = "merge"
	cmdValidate = "validate"
	cmdDiff     = "diff"

	flagHelp = "--help"
	cmdHelp  = "help"

	typeSeccomp  = "seccomp"
	typeAppArmor = "apparmor"
	typeLandlock = "landlock"

	strategyIntersect = "intersect"
	strategyUnion     = "union"

	formatJSON  = "json"
	formatHuman = "human"
)

const usage = `Usage: spm <command> [options] [files...]

Commands:
  merge      Merge one or more security profiles
  validate   Validate one or more security profiles
  diff       Compare two security profiles
  version    Print the version

Run 'spm <command> --help' for details on each command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func detectProfileType(data [][]byte) string {
	if len(data) == 0 {
		return ""
	}

	var fields map[string]json.RawMessage

	err := json.Unmarshal(data[0], &fields)
	if err != nil {
		return ""
	}

	if _, ok := fields["defaultAction"]; ok {
		return typeSeccomp
	}

	for _, key := range []string{
		"handledAccessFs", "handledAccessNet", "pathRules", "netRules", "scoped",
	} {
		if _, ok := fields[key]; ok {
			return typeLandlock
		}
	}

	for _, key := range []string{
		"executable", "filesystem", "capability", "network",
	} {
		if _, ok := fields[key]; ok {
			return typeAppArmor
		}
	}

	return ""
}

func openOutput(
	path string, defaultWriter io.Writer, stderr io.Writer,
) (io.Writer, func(), int) {
	if path == "" {
		return defaultWriter, func() {}, 0
	}

	const ownerReadWrite = 0o600

	file, err := os.OpenFile(
		filepath.Clean(path),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		ownerReadWrite,
	)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: creating output file: %v\n", err)

		return nil, func() {}, 1
	}

	cleanup := func() {
		err := file.Close()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: closing output file: %v\n", err)
		}
	}

	return file, cleanup, 0
}

func validateFormat(format string, stderr io.Writer) int {
	if format != formatJSON && format != formatHuman {
		_, _ = fmt.Fprintf(
			stderr, "error: unknown format %q (use json or human)\n", format,
		)

		return exitUsage
	}

	return 0
}

func validateProfileType(profileType string, stderr io.Writer) int {
	if profileType != "" &&
		profileType != typeSeccomp &&
		profileType != typeAppArmor &&
		profileType != typeLandlock {
		_, _ = fmt.Fprintf(
			stderr,
			"error: unknown type %q (use seccomp, apparmor, or landlock)\n",
			profileType,
		)

		return exitUsage
	}

	return 0
}

func resolveProfileType(
	profileType *string, data [][]byte, stderr io.Writer,
) int {
	if *profileType != "" {
		return 0
	}

	*profileType = detectProfileType(data)

	if *profileType == "" {
		_, _ = fmt.Fprintln(
			stderr,
			"error: could not detect profile type from input, use --type",
		)

		return exitUsage
	}

	_, _ = fmt.Fprintf(
		stderr, "auto-detected profile type: %s\n", *profileType,
	)

	return 0
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)

		return exitUsage
	}

	switch args[0] {
	case cmdMerge:
		return runMerge(args[1:], stdin, stdout, stderr)
	case cmdValidate:
		return runValidate(args[1:], stdin, stdout, stderr)
	case cmdDiff:
		return runDiff(args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "spm %s\n", version)

		return 0
	case flagHelp, "-h", cmdHelp:
		_, _ = fmt.Fprint(stdout, usage)

		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[0], usage)

		return exitUsage
	}
}
