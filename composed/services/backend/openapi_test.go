package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite "+interfaceArtifactPath+" from the routes this backend serves")

// TestInterfaceArtifactIsCurrent holds the committed interface document to the
// routes this backend actually serves. It is rendered from the server itself,
// so a route added without re-rendering fails here rather than reaching the
// authority with no row to check it against.
//
// `go generate ./...` runs this with -update.
func TestInterfaceArtifactIsCurrent(t *testing.T) {
	rendered, err := renderInterfaceArtifact(".")
	if err != nil {
		t.Fatalf("cannot render %s: %v", interfaceArtifactPath, err)
	}
	path := filepath.FromSlash(interfaceArtifactPath)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, rendered, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v\nRun `go generate ./...` and commit it.", interfaceArtifactPath, err)
	}
	if !bytes.Equal(bytes.TrimSpace(committed), bytes.TrimSpace(rendered)) {
		t.Fatalf("%s is not what this backend serves. Run `go generate ./...` and commit it.", interfaceArtifactPath)
	}
}
