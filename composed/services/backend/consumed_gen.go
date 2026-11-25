// Code generated from solution.codefly.yaml by the codefly.dev/solution-go
// agent. DO NOT EDIT.
//
// api.consumes is the one place this solution says which modules it may reach.
// These names are that list, so consumes.go cannot name a module the manifest
// does not — nor miss one it does. Regenerate it with `codefly sync`;
// consumes_test.go fails while this file and the manifest disagree.

package main

// consumedAs names each consumed module, so consumes.go spells no `as` by hand.
var consumedAs = struct {
	Documents string
}{
	Documents: "documents",
}

// consumedAsAll is the same list, in manifest order.
var consumedAsAll = []string{"documents"}
