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

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
)

const (
	exitDiff         = 1
	diffProfileCount = 2

	diffUsage = `Usage: spm diff [options] <file1> <file2>

Compare two security profiles and show their differences.
Reads from stdin (as a JSON array of exactly 2 profiles) when no files are provided.
Exit code 0 means equal, 1 means different, 2 means error.

Options:
`
)

var errDiffRequiresTwo = errors.New("diff requires exactly 2 profiles")

func runDiff(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("diff", flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.Usage = func() {
		_, _ = fmt.Fprint(stderr, diffUsage)

		flags.PrintDefaults()
	}

	profileType := flags.String(
		"type", "", "profile type: seccomp, apparmor, landlock (auto-detected if omitted)",
	)
	format := flags.String("format", formatJSON, "output format: json, human")
	output := flags.String("output", "", "write output to file (default: stdout)")

	err := flags.Parse(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return exitUsage
	}

	if code := validateFormat(*format, stderr); code != 0 {
		return code
	}

	if code := validateProfileType(*profileType, stderr); code != 0 {
		return code
	}

	data, err := readDiffInputs(flags.Args(), stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	kind, code := resolveKind(*profileType, data, stderr)
	if code != 0 {
		return code
	}

	var out bytes.Buffer

	code = kind.diff(data, *format, &out, stderr)
	if code != 0 && code != exitDiff {
		return code
	}

	// Exit code 1 means "different" for diff, so a failed flush is a usage
	// error like every other diff failure.
	if flushOutput(*output, out.Bytes(), stdout, stderr) != 0 {
		return exitUsage
	}

	return code
}

func readDiffInputs(
	paths []string, stdin io.Reader,
) ([][]byte, error) {
	if len(paths) == 0 {
		data, err := readFromStdin(stdin)
		if err != nil {
			return nil, err
		}

		if len(data) != diffProfileCount {
			return nil, fmt.Errorf(
				"got %d from stdin: %w", len(data), errDiffRequiresTwo,
			)
		}

		return data, nil
	}

	if len(paths) != diffProfileCount {
		return nil, fmt.Errorf(
			"got %d files: %w", len(paths), errDiffRequiresTwo,
		)
	}

	data, err := readInputs(paths, stdin)
	if err != nil {
		return nil, err
	}

	// A "-" argument may expand to several profiles when stdin holds a
	// JSON array.
	if len(data) != diffProfileCount {
		return nil, fmt.Errorf(
			"got %d profiles: %w", len(data), errDiffRequiresTwo,
		)
	}

	return data, nil
}

type equalChecker interface {
	IsEqual() bool
}

func diffProfiles[T any, D equalChecker](
	data [][]byte,
	format string,
	diffFn func(*T, *T) (*D, error),
	formatFn func(*D) string,
	stdout, stderr io.Writer,
) int {
	profiles, err := unmarshalAll[T](data, false, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	result, err := diffFn(profiles[0], profiles[1])
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "error: %v\n", err)

		return exitUsage
	}

	if code := writeOutput(result, formatFn(result), format, stdout, stderr); code != 0 {
		return exitUsage
	}

	if !(*result).IsEqual() {
		return exitDiff
	}

	return 0
}
