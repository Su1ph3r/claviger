package corpus

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// safeMethods are read-only HTTP methods included by default.
var safeMethods = map[string]bool{
	"GET":     true,
	"HEAD":    true,
	"OPTIONS": true,
}

// unsafeMethods are state-changing methods included only when includeUnsafe.
var unsafeMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
}

type openAPISpec struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

func loadOpenAPI(data []byte, includeUnsafe bool) ([]Request, error) {
	// yaml.Unmarshal also accepts JSON, so this covers both spec formats.
	var spec openAPISpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, err
	}
	var reqs []Request
	for path, ops := range spec.Paths {
		for method := range ops {
			m := strings.ToUpper(method)
			if safeMethods[m] || (includeUnsafe && unsafeMethods[m]) {
				reqs = append(reqs, Request{Method: m, Path: path})
			}
		}
	}
	// Go map iteration is randomized, so sort by path then method to give a stable
	// corpus order run-to-run.
	sort.Slice(reqs, func(i, j int) bool {
		if reqs[i].Path != reqs[j].Path {
			return reqs[i].Path < reqs[j].Path
		}
		return reqs[i].Method < reqs[j].Method
	})
	return reqs, nil
}
