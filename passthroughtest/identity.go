package passthroughtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"
)

// The trust domain and the two identities this fake host issues.
//
// sdk-go#51 holds the mint endpoint to WHICH party it is, read from the single
// URI SAN on its leaf, so the fake host needs a real cell rather than
// httptest's shared certificate: that one carries no SPIFFE ID at all, and a
// mint client configured with AdmittedPeers refuses it — correctly. The seam
// exists to run a consumer's passthrough against the posture a deployment has,
// so the fake host grew a CA instead of the client losing the check.
const (
	trustDomain       = "passthroughtest"
	mintPeerIdentity  = "spiffe://" + trustDomain + "/ns/host/sa/mint"
	workloadIdentitry = "spiffe://" + trustDomain + "/ns/solutions/sa/passthroughtest"
)

// mintCell is the fake host's own certificate authority: a root, the mint
// endpoint's leaf, and the workload leaf the mint client presents.
type mintCell struct {
	roots    *x509.CertPool
	mint     tls.Certificate
	workload tls.Certificate
}

// newMintCell issues the cell. Everything is ephemeral and in memory: this is
// a test seam, and a key on disk would outlive the run that made it.
func newMintCell() (*mintCell, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("the fake host could not generate its root key: %w", err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: trustDomain + " root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("the fake host could not sign its root: %w", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("the fake host's root does not parse: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	// The mint endpoint. It is a server AND the thing whose identity the client
	// admits, so it carries exactly one URI SAN and the names httptest serves
	// on.
	mint, err := leaf(root, rootKey, 2, mintPeerIdentity,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")})
	if err != nil {
		return nil, err
	}
	// The workload. One URI SAN as well, because this is what the real mint
	// endpoint reads to decide which solution is asking.
	workload, err := leaf(root, rootKey, 3, workloadIdentitry,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	if err != nil {
		return nil, err
	}
	return &mintCell{roots: roots, mint: *mint, workload: *workload}, nil
}

// leaf issues one end-entity certificate with a single SPIFFE URI SAN.
func leaf(
	root *x509.Certificate, rootKey *ecdsa.PrivateKey, serial int64, identity string,
	usages []x509.ExtKeyUsage, dnsNames []string, ips []net.IP,
) (*tls.Certificate, error) {
	spiffeID, err := url.Parse(identity)
	if err != nil {
		return nil, fmt.Errorf("the fake host's identity %q does not parse: %w", identity, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("the fake host could not generate a key for %s: %w", identity, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: identity},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           usages,
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{spiffeID},
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("the fake host could not sign %s: %w", identity, err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
