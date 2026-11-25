//go:build composition

// A Work Context replayed as issued, and the authority stopped.
//
// The edge issues or drops what it holds per call, so no call made through it
// replays a token. These two scenarios stand where the edge stands: they sign
// a fixture person in at the edge, ask the authority for that session's Work
// Context at the solution exactly as the edge does (Issue, as the person, for
// the solution's audience), and send it to the scaffold's backend themselves,
// on the header the edge uses. From the backend on nothing differs from a
// page's call: the runtime asks the authority who the viewer is, is issued a
// child through the solution's binding and relays to the hop and the store.
//
// Every address is the run's: the edge's from the scenario library, the
// authority's and the backend's from what the dependency session delivered to
// the anchor. Nothing is written down.
package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"github.com/codefly-dev/authority/libraries/authority-client/go/host"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// workContextHeader is the header a Work Context travels in to a module
// (hop.WorkContextKey, the runtime's WorkContextHeader).
const workContextHeader = "x-codefly-work-context"

// delivered is deliveredAddress (tap_composition_test.go), for a scenario.
func delivered(t *testing.T, module, service, endpoint string) string {
	t.Helper()
	address, err := deliveredAddress(module, service, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

var (
	hostOnce sync.Once
	hostConn *grpc.ClientConn
	hostErr  error
)

// authority is the test's own connection to the local authority.
func authority(t *testing.T) *grpc.ClientConn {
	t.Helper()
	address := delivered(t, "authority", "local", "grpc")
	hostOnce.Do(func() {
		hostConn, hostErr = grpc.NewClient(address, host.DialOptions(insecure.NewCredentials())...)
	})
	if hostErr != nil {
		t.Fatal(hostErr)
	}
	return hostConn
}

// answer is one HTTP answer, read as a Connect refusal when it is one.
type answer struct {
	status       int
	code, reason string
	body         []byte
}

func (a answer) String() string {
	return fmt.Sprintf("%d %s: %s %s", a.status, a.code, a.reason, a.body)
}

// direct bounds every call these scenarios make themselves: beyond the
// authority's own call timeout at the edge and in the runtime (10s each).
var direct = &http.Client{Timeout: 25 * time.Second}

func send(method, url string, header map[string]string, request any) (answer, error) {
	var body io.Reader
	if request != nil {
		payload, err := json.Marshal(request)
		if err != nil {
			return answer{}, err
		}
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := direct.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return answer{}, err
	}
	out := answer{status: res.StatusCode, body: raw}
	if res.StatusCode != http.StatusOK {
		var refusal struct{ Code, Message, Error string }
		if json.Unmarshal(raw, &refusal) != nil {
			refusal.Message = strings.TrimSpace(string(raw))
		}
		out.code, out.reason = refusal.Code, refusal.Message+refusal.Error
	}
	return out, nil
}

// session is a fixture person's own session, opened at the edge as their
// browser opens it.
type session struct{ person, bearer string }

func signIn(t *testing.T, id string) session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	listed, err := sessionv1.NewSessionServiceClient(authority(t)).ListFixturePeople(ctx, &sessionv1.ListFixturePeopleRequest{})
	if err != nil {
		t.Fatalf("the host lists no fixture people: %v", err)
	}
	for _, p := range listed.GetPeople() {
		if p.GetPersonId() != id {
			continue
		}
		got, err := send(http.MethodPost, composed.Origin()+"/auth/sign-in", map[string]string{"Origin": composed.Origin()},
			map[string]string{"fixtureToken": p.GetFixtureToken()})
		if err != nil {
			t.Fatalf("sign in %s at the edge: %v", id, err)
		}
		var opened struct{ Bearer string }
		if json.Unmarshal(got.body, &opened) != nil || opened.Bearer == "" {
			t.Fatalf("sign in %s at the edge: %s", id, got)
		}
		return session{id, opened.Bearer}
	}
	t.Fatalf("%q is not a fixture person of this host", id)
	return session{}
}

// issued is the session's Work Context at the solution, asked of the
// authority as the edge asks it for a call with no page.
func (s session) issued(t *testing.T) (string, error) {
	t.Helper()
	return s.issuedAt(t, solution)
}

// issuedAt is the session's Work Context at audience: the solution, or a
// module whose page calls the edge routes to the hop.
func (s session) issuedAt(t *testing.T, audience string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+s.bearer), 10*time.Second)
	defer cancel()
	got, err := authorityv1.NewAuthorityServiceClient(authority(t)).Issue(ctx, &authorityv1.IssueRequest{
		As: &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}}, Audience: audience})
	if err != nil {
		return "", err
	}
	if got.GetToken() == "" {
		return "", fmt.Errorf("the authority issued no Work Context")
	}
	return got.GetToken(), nil
}

const getDocument = "/v1/" + solution + "/modules/documents/documents.v1.DocumentsService/GetDocument"

// presents sends token to the scaffold's backend with a read of d: the call
// the edge makes, with the Work Context it would send.
func presents(t *testing.T, token string, d document) (answer, error) {
	t.Helper()
	return send(http.MethodPost, "http://"+delivered(t, solution, "backend", "http")+getDocument,
		map[string]string{workContextHeader: token}, d.read())
}

// through sends the same read through the edge on s, with no token of the
// test's own.
func (s session) through(d document) (answer, error) {
	return send(http.MethodPost, composed.Origin()+getDocument, map[string]string{"Authorization": "Bearer " + s.bearer}, d.read())
}

func answered(t *testing.T, what string, got answer, err error, d document) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	var read struct {
		Document struct{ Entry struct{ EntryID string } }
	}
	_ = json.Unmarshal(got.body, &read)
	if got.status != http.StatusOK || read.Document.Entry.EntryID != d.entry {
		t.Fatalf("%s: want the document %s, got %s", what, d.entry, got)
	}
}

// A Work Context replayed as issued is refused once the team's grant is gone.
// Carol holds the user role through its team alone. Her session's Work
// Context, sent to the backend, reads Dana's document: the token is good.
// Dana revokes the role from the team. The same token, byte for byte, sent
// again on the next call, is refused as a permission and answers nothing of
// the document; the authority issues her session no other. Granted back, a
// context issued then reads again: the refusal was the revocation.
func TestComposedAHeldWorkContextReplayedAfterTheRevocationIsRefused(t *testing.T) {
	team := userTeam(t)
	d := write(t, people.Admin, "replayed")
	carol := signIn(t, people.User)
	token, err := carol.issued(t)
	if err != nil {
		t.Fatalf("Carol, seated through the team, is issued no Work Context at %s: %v", solution, err)
	}
	got, err := presents(t, token, d)
	answered(t, "Carol's Work Context, sent to the backend while her team holds the role", got, err, d)

	seated := true
	t.Cleanup(func() {
		if !seated {
			change(t, people.Admin, "GrantRole", team)
		}
	})
	change(t, people.Admin, "RevokeRole", team)
	seated = false

	replayed, err := presents(t, token, d)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.status != http.StatusForbidden || replayed.code != "permission_denied" {
		t.Errorf("the Work Context issued before the revocation, replayed after it: want 403 permission_denied, got %s", replayed)
	}
	if strings.Contains(string(replayed.body), d.version) {
		t.Errorf("the replayed Work Context is answered the document's version: %s", replayed)
	}
	t.Logf("replayed after the revocation: %s", replayed)
	if again, err := carol.issued(t); err == nil {
		t.Errorf("Carol's session is issued a Work Context at %s after the team's role was revoked (%d bytes)", solution, len(again))
	} else if !strings.Contains(err.Error(), noRole) {
		t.Errorf("Carol's session is refused a Work Context for another reason than %q: %v", noRole, err)
	}

	change(t, people.Admin, "GrantRole", team)
	seated = true
	fresh, err := carol.issued(t)
	if err != nil {
		t.Fatalf("the role granted back to the team, Carol is issued no Work Context: %v", err)
	}
	got, err = presents(t, fresh, d)
	answered(t, "a Work Context issued after the role was granted back", got, err, d)
}

// failedClosed holds the two calls made with the authority stopped or gone
// (how) to an unavailable answer that carries nothing of d: the backend's by
// Connect's name for it, the edge's in the edge's own words, each 503.
func failedClosed(t *testing.T, how string, d document, held answer, heldErr error, edge answer, edgeErr error) {
	t.Helper()
	for _, c := range []struct {
		name string
		got  answer
		err  error
		ok   bool
	}{
		{"the Work Context allowed a moment ago, sent to the backend", held, heldErr,
			held.status == http.StatusServiceUnavailable && held.code == "unavailable"},
		{"the session, through the edge", edge, edgeErr,
			edge.status == http.StatusServiceUnavailable && (edge.code == "unavailable" || strings.Contains(edge.reason, "the authority could not answer"))},
	} {
		if c.err != nil {
			t.Errorf("with the authority %s, %s: no answer at all: %v", how, c.name, c.err)
			continue
		}
		if !c.ok {
			t.Errorf("with the authority %s, %s: want 503 unavailable, got %s", how, c.name, c.got)
		}
		if strings.Contains(string(c.got.body), d.version) || strings.Contains(string(c.got.body), d.entry) {
			t.Errorf("with the authority %s, %s is answered something of the document: %s", how, c.name, c.got)
		}
		t.Logf("with the authority %s, %s: %s", how, c.name, c.got)
	}
}

// listeners are the processes listening on the address the run resolved.
func listeners(t *testing.T, address string) []int {
	t.Helper()
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("lsof", "-nP", "-t", "-iTCP:"+port, "-sTCP:LISTEN").Output()
	if err != nil {
		t.Fatalf("no process listens on the authority's address %s (lsof: %v)", address, err)
	}
	var pids []int
	for _, field := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(field); err == nil {
			pids = append(pids, pid)
		}
	}
	if len(pids) == 0 {
		t.Fatalf("no process listens on the authority's address %s", address)
	}
	return pids
}

// The authority stopped, nothing is answered on what was allowed a moment
// ago. Carol's Work Context reads the document through the backend, and her
// session reads it through the edge. The authority's process is stopped
// (SIGSTOP: it holds its address and answers nothing, the outage no
// connection refusal announces). The same token sent to the backend again is
// unavailable, by name, and carries nothing of the document: the runtime
// holds no allow from the call before, and reaches no hop without the
// authority's answer. The session's call through the edge is unavailable too.
// The authority continued, the same token and the same session read again.
//
// STOPGAP: the process is found by the address the run resolved, because
// neither the scenario library nor the dependency session stops one service
// of a run (Composition.Stop, in the same brief as delivered's).
func TestComposedTheAuthorityStoppedTheRelayFailsClosed(t *testing.T) {
	userTeam(t)
	d := write(t, people.Admin, "authority-stopped")
	carol := signIn(t, people.User)
	token, err := carol.issued(t)
	if err != nil {
		t.Fatal(err)
	}
	got, err := presents(t, token, d)
	answered(t, "Carol's Work Context, sent to the backend with the authority up", got, err, d)
	got, err = carol.through(d)
	answered(t, "Carol's session, through the edge with the authority up", got, err, d)

	pids := listeners(t, delivered(t, "authority", "local", "grpc"))
	stopped := false
	resume := func() {
		if stopped {
			for _, pid := range pids {
				_ = syscall.Kill(pid, syscall.SIGCONT)
			}
			stopped = false
		}
	}
	defer resume()
	for _, pid := range pids {
		if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
			t.Fatalf("stop the authority (pid %d): %v", pid, err)
		}
	}
	stopped = true

	// Both calls wait out the authority's call timeout; made together.
	var held, edge answer
	var heldErr, edgeErr error
	var wg sync.WaitGroup
	wg.Add(2)
	began := time.Now()
	go func() { defer wg.Done(); held, heldErr = presents(t, token, d) }()
	go func() { defer wg.Done(); edge, edgeErr = carol.through(d) }()
	wg.Wait()
	waited := time.Since(began)
	resume()

	failedClosed(t, "stopped", d, held, heldErr, edge, edgeErr)
	t.Logf("the two calls were refused in %s", waited.Round(time.Millisecond))

	got, err = presents(t, token, d)
	answered(t, "the same Work Context, the authority continued", got, err, d)
	got, err = carol.through(d)
	answered(t, "the same session through the edge, the authority continued", got, err, d)
}
