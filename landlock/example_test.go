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
	"fmt"

	"github.com/saschagrunert/security-profiles-merger/landlock"
)

func ExampleIntersect() {
	baseline := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
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

	profile := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Intersect(baseline, profile)
	if err != nil {
		panic(err)
	}

	fmt.Println("HandledAccessFS:", result.HandledAccessFS)

	for _, rule := range result.PathRules {
		fmt.Println("Path:", rule.Path, "->", rule.AccessFS)
	}

	// Output:
	// HandledAccessFS: [read_file write_file]
	// Path: /etc -> [read_file]
}

func ExampleValidate() {
	profile := &landlock.Profile{
		HandledAccessFS:  []landlock.FSAccessRight{"bogus_right"},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules:        nil,
		NetRules:         nil,
	}

	err := landlock.Validate(profile)
	fmt.Println(err)

	// Output:
	// HandledAccessFS: unknown access right "bogus_right"
}

func ExampleValidateStrict() {
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
	fmt.Println(err)

	// Output:
	// PathRules[0]: right "write_file": rule grants unhandled access right
}

func ExampleFormatProfile() {
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
			},
		}},
		NetRules: nil,
	}

	fmt.Println(landlock.FormatProfile(profile))

	// Output:
	// Profile{fs:read_file /etc(read_file)}
}

func ExampleDiff() {
	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessExecute,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathTmp,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println("Equal:", diff.Equal)
	fmt.Println(landlock.FormatDiff(diff))

	// Output:
	// Equal: false
	// Diff{fs:-write_file,+execute -/etc(read_file) +/tmp(write_file)}
}

func ExampleFormatDiff() {
	left := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	right := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	diff, err := landlock.Diff(left, right)
	if err != nil {
		panic(err)
	}

	fmt.Println(landlock.FormatDiff(diff))

	// Output:
	// Diff{equal}
}

func ExampleUnion() {
	recording1 := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathEtc,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessReadFile,
			},
		}},
		NetRules: nil,
	}

	recording2 := &landlock.Profile{
		HandledAccessFS: []landlock.FSAccessRight{
			landlock.FSAccessReadFile,
			landlock.FSAccessWriteFile,
		},
		HandledAccessNet: nil,
		Scoped:           nil,
		PathRules: []landlock.PathRule{{
			Path: pathHome,
			AccessFS: []landlock.FSAccessRight{
				landlock.FSAccessWriteFile,
			},
		}},
		NetRules: nil,
	}

	result, err := landlock.Union(recording1, recording2)
	if err != nil {
		panic(err)
	}

	fmt.Println("HandledAccessFS:", result.HandledAccessFS)

	for _, rule := range result.PathRules {
		fmt.Println("Path:", rule.Path, "->", rule.AccessFS)
	}

	// Output:
	// HandledAccessFS: [read_file write_file]
	// Path: /etc -> [read_file]
	// Path: /home -> [write_file]
}
