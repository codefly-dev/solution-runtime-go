package solution

import "testing"

// TestListenPortReadsEitherAddressForm pins the two shapes Codefly hands a
// service for its own endpoint: a rendered cell writes the bare host:port, a
// local run a URL. The bare form is the one url.Parse misreads as a scheme.
func TestListenPortReadsEitherAddressForm(t *testing.T) {
	for address, want := range map[string]string{
		"localhost:8080":         "8080",
		"http://localhost:8080":  "8080",
		"http://127.0.0.1:41234": "41234",
		"[::1]:9000":             "9000",
		"localhost":              "",
		"":                       "",
	} {
		if got := listenPort(address); got != want {
			t.Errorf("listenPort(%q) = %q, want %q", address, got, want)
		}
	}
}
