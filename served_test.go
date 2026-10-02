package solution

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Coverage of what a solution still *serves*, restored under the TLS harness.
//
// It lived in the registration test files this PR deleted, which made it look
// like coverage of registration; it is not. Nothing about these documents is
// registered any more — they are published at fixed paths and the host fetches
// them, which is why deleting them was the one thing the host asked me not to
// do — and the asset cache policy is what a browser does with a build. All of
// it survives the cutover, so all of it keeps its test.

// TestServedDocumentsDeclareOneSetOfMajors: a reader checks both documents, so
// a bump of either constant must not leave one announcing the old major while
// the other announces the new one.
func TestServedDocumentsDeclareOneSetOfMajors(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID, Title: testSolutionTitle}), mint)

	var capabilities map[string]any
	readServed(t, solution, "/.well-known/capabilities", &capabilities)
	var served map[string]any
	readServed(t, solution, "/.well-known/solution.json", &served)

	if got, want := capabilities["schemaVersion"], served["schemaVersion"]; got != want {
		t.Errorf("capabilities schemaVersion = %v, the manifest says %v", got, want)
	}
	frontend, ok := served["frontend"].(map[string]any)
	if !ok {
		t.Fatalf("the served manifest has no frontend block: %v", served)
	}
	if got, want := capabilities["contractMajor"], frontend["hostContract"]; got != want {
		t.Errorf("capabilities contractMajor = %v, the manifest's frontend.hostContract says %v", got, want)
	}
	if got := capabilities["contract"]; got != testSolutionID {
		t.Errorf("capabilities contract = %v, want the solution's own id: the default used to be a product's name, so every solution that left it unset announced that product's contract", got)
	}
	if got := frontend["manifestUrl"]; got != federationManifestPath {
		t.Errorf("frontend.manifestUrl = %v, want the path on this backend", got)
	}
	if got := served["id"]; got != testSolutionID {
		t.Errorf("served id = %v, want %q", got, testSolutionID)
	}
}

// TestAssetsAreServedWithTheRightCachePolicy: a content-hashed file never
// changes under its name, so it is cached for good; everything else — above all
// the federation manifest and the remote entry, whose names are fixed so the
// host can find them — must be revalidated, or a browser keeps a manifest
// naming chunks the redeployed solution no longer serves. A 404 for a hashed
// name, asked of an old replica mid-rollout, must not be cached for a year
// under the name the next build will serve.
func TestAssetsAreServedWithTheRightCachePolicy(t *testing.T) {
	assets := t.TempDir()
	writeFile(t, filepath.Join(assets, "mf-manifest.json"), `{"name":"widgets"}`)
	writeFile(t, filepath.Join(assets, "page.3f9a1c2b.js"), "console.log(1)")

	t.Setenv("ASSETS_DIR", assets)
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID}), mint)

	for _, tc := range []struct {
		path   string
		status int
		cache  string
	}{
		{"/assets/page.3f9a1c2b.js", http.StatusOK, "public, max-age=31536000, immutable"},
		{"/assets/mf-manifest.json", http.StatusOK, "no-cache"},
		{"/assets/page.0badc0de.js", http.StatusNotFound, "no-cache"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := solution.client.Get(solution.base + tc.path)
			if err != nil {
				t.Fatalf("GET %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", resp.StatusCode, tc.status)
			}
			if got := resp.Header.Get("cache-control"); got != tc.cache {
				t.Errorf("cache-control = %q, want %q", got, tc.cache)
			}
			if got := resp.Header.Get("access-control-allow-origin"); got == "" {
				t.Error("the asset was served without CORS, so a host origin could not load it")
			}
		})
	}
}

// TestTheAssetsOfAnEmbeddedBuildAreServedFromTheBinary: a solution shipping its
// frontend in the binary reads nothing from disk to serve it, so it runs with a
// read-only root filesystem and cannot drift from the build it was compiled
// with.
func TestTheAssetsOfAnEmbeddedBuildAreServedFromTheBinary(t *testing.T) {
	// No assets directory on disk at all: a solution shipping its frontend in
	// the binary reads nothing to serve it.
	t.Setenv("ASSETS_DIR", filepath.Join(t.TempDir(), "does-not-exist"))
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID, Assets: embeddedBuild{}}), mint)

	resp, err := solution.client.Get(solution.base + "/assets/mf-manifest.json")
	if err != nil {
		t.Fatalf("GET the embedded manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200 served from the binary with no assets directory on disk", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "embedded") {
		t.Errorf("body = %q, want the embedded manifest", body)
	}
}

// readServed decodes one document this solution publishes.
func readServed(t *testing.T, solution *booted, path string, into any) {
	t.Helper()
	resp, err := solution.client.Get(solution.base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

// embeddedBuild stands in for a go:embed of a frontend build.
type embeddedBuild struct{}

func (embeddedBuild) Open(name string) (fs.File, error) {
	if name != "mf-manifest.json" {
		return nil, os.ErrNotExist
	}
	return &embeddedFile{Reader: strings.NewReader(`{"name":"embedded"}`)}, nil
}

type embeddedFile struct {
	*strings.Reader
}

func (f *embeddedFile) Stat() (fs.FileInfo, error) { return embeddedInfo{size: f.Size()}, nil }
func (f *embeddedFile) Close() error               { return nil }

type embeddedInfo struct{ size int64 }

func (embeddedInfo) Name() string       { return "mf-manifest.json" }
func (i embeddedInfo) Size() int64      { return i.size }
func (embeddedInfo) Mode() fs.FileMode  { return 0o444 }
func (embeddedInfo) ModTime() time.Time { return time.Time{} }
func (embeddedInfo) IsDir() bool        { return false }
func (embeddedInfo) Sys() any           { return nil }
