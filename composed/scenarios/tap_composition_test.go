//go:build composition

// The child the runtime is issued, held and replayed.
//
// The backend relays a page's call to the hop with a CHILD of the viewer's
// Work Context, issued to it through the solution's binding, and nothing
// outside the backend ever sees that child. So this run puts a tap where the
// composition says the consumed module is (codefly-base/DOCUMENTS_ENDPOINT, a
// composition value, set in TestMain): a listener of the test's own that sends
// every call on to the hop the run resolved, byte for byte with its metadata,
// and keeps what it sent. The scaffold's code is not touched and the hop
// decides every call as it does without the tap; what the tap adds is that a
// call the backend made can be made again, exactly.
package scenarios

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/codefly-dev/core/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// bytesCodec carries a message as the bytes it arrived in.
type bytesCodec struct{}

func (bytesCodec) Name() string { return "proto" }
func (bytesCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("the tap carries bytes, not %T", v)
	}
	return *b, nil
}
func (bytesCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("the tap carries bytes, not %T", v)
	}
	*b = append((*b)[:0], data...)
	return nil
}

// relayedCall is one call the backend made to the hop, as it made it.
type relayedCall struct {
	method   string
	metadata metadata.MD
	request  []byte
}

// tap is the listener the backend is told the consumed module is at.
type tap struct {
	address string
	mu      sync.Mutex
	calls   []relayedCall
	once    sync.Once
	hop     *grpc.ClientConn
	hopErr  error
}

var relayTap *tap

// startTap listens on a port of the system's choosing, before the composition
// starts: its address is the value the composition is given.
func startTap() (*tap, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tp := &tap{address: l.Addr().String()}
	server := grpc.NewServer(grpc.ForceServerCodec(bytesCodec{}), grpc.UnknownServiceHandler(tp.relay))
	go func() { _ = server.Serve(l) }()
	return tp, nil
}

// carried is the metadata of a call that is the caller's to send again: what
// the transport writes for itself is left out.
func carried(md metadata.MD) metadata.MD {
	out := metadata.MD{}
	for key, values := range md {
		if strings.HasPrefix(key, ":") || strings.HasPrefix(key, "grpc-") || key == "content-type" || key == "user-agent" || key == "te" {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}

func (tp *tap) toHop() (*grpc.ClientConn, error) {
	tp.once.Do(func() {
		address, err := deliveredAddress("authority", "hop", "grpc")
		if err != nil {
			tp.hopErr = err
			return
		}
		tp.hop, tp.hopErr = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	})
	return tp.hop, tp.hopErr
}

// relay sends one unary call on to the hop and keeps it.
func (tp *tap) relay(_ any, stream grpc.ServerStream) error {
	method, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		return status.Error(codes.Internal, "the tap was called with no method")
	}
	incoming, _ := metadata.FromIncomingContext(stream.Context())
	call := relayedCall{method: method, metadata: carried(incoming)}
	if err := stream.RecvMsg(&call.request); err != nil {
		return err
	}
	tp.mu.Lock()
	tp.calls = append(tp.calls, call)
	tp.mu.Unlock()
	answer, header, trailer, err := tp.send(stream.Context(), call)
	_ = stream.SetHeader(header)
	stream.SetTrailer(trailer)
	if err != nil {
		return err
	}
	return stream.SendMsg(&answer)
}

// send makes call at the hop, exactly as it was made.
func (tp *tap) send(ctx context.Context, call relayedCall) (answer []byte, header, trailer metadata.MD, err error) {
	hop, err := tp.toHop()
	if err != nil {
		return nil, nil, nil, status.Error(codes.Unavailable, "the tap reaches no hop: "+err.Error())
	}
	err = hop.Invoke(metadata.NewOutgoingContext(ctx, call.metadata), call.method, &call.request, &answer,
		grpc.ForceCodec(bytesCodec{}), grpc.Header(&header), grpc.Trailer(&trailer))
	return answer, header, trailer, err
}

// last is the latest call of method the backend made since mark.
func (tp *tap) last(t *testing.T, mark int, method string) relayedCall {
	t.Helper()
	tp.mu.Lock()
	defer tp.mu.Unlock()
	for i := len(tp.calls) - 1; i >= mark; i-- {
		if strings.HasSuffix(tp.calls[i].method, "/"+method) {
			return tp.calls[i]
		}
	}
	t.Fatalf("the backend relayed no %s through the tap: the composition does not send its module calls where DOCUMENTS_ENDPOINT says", method)
	return relayedCall{}
}

func (tp *tap) mark() int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return len(tp.calls)
}

// deliveredAddress is the address the run delivered to the anchor for a
// dependency's endpoint, as the scenario library reads it
// (Composition.address).
//
// STOPGAP: the library keeps its dependency session to itself and offers no
// address but the edge's, so this reads the unexported field. It goes when
// the library exports one (AGENTS.md, The composed scenarios).
func deliveredAddress(module, service, endpoint string) (string, error) {
	if composed == nil {
		return "", fmt.Errorf("the composition has not started")
	}
	field := reflect.ValueOf(composed).Elem().FieldByName("deps")
	if !field.IsValid() {
		return "", fmt.Errorf("the scenario library's Composition no longer holds its dependency session as deps")
	}
	deps := *(**sdk.Dependencies)(unsafe.Pointer(field.UnsafeAddr()))
	key := func(name string) string { return strings.ToUpper(strings.ReplaceAll(name, "-", "_")) }
	prefix := "CODEFLY__ENDPOINT__" + key(module) + "__" + key(service) + "__" + key(endpoint) + "__"
	for name, value := range deps.EnvironmentVariables() {
		if strings.HasPrefix(name, prefix) && value != "" {
			return strings.TrimPrefix(strings.TrimPrefix(value, "http://"), "https://"), nil
		}
	}
	return "", fmt.Errorf("the run delivered no address of %s/%s/%s: the anchor must depend on it", module, service, endpoint)
}

// A child issued before the revocation, replayed at the hop, is refused.
// Carol, seated through the team alone, reads Dana's document through the
// backend: the runtime is issued a child of her Work Context through the
// solution's binding and sends it to the hop, and the tap keeps that call.
// Made again as it was made, straight at the hop, it reads the document: the
// child is good and a replay is a call like any other. Dana revokes the role
// from the team. The same call, the same child, byte for byte, is refused by
// the hop as a permission and answers nothing; no backend and no runtime
// check stand between the test and the hop here. Granted back, Carol reads
// through the backend again.
func TestComposedAChildIssuedBeforeTheRevocationIsRefusedAtTheHop(t *testing.T) {
	team := userTeam(t)
	d := write(t, people.Admin, "child-replayed")
	mark := relayTap.mark()
	reads(t, people.User, d)
	call := relayTap.last(t, mark, "GetDocument")
	child := call.metadata.Get(workContextHeader)
	if len(child) != 1 || child[0] == "" {
		t.Fatalf("the backend's call to the hop carried %d Work Contexts, want the one child", len(child))
	}
	replay := func() ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		answer, _, _, err := relayTap.send(ctx, call)
		return answer, err
	}
	answer, err := replay()
	if err != nil || !strings.Contains(string(answer), d.entry) {
		t.Fatalf("the child, replayed at the hop while the team holds the role: want the document %s, got %d bytes, %v", d.entry, len(answer), err)
	}

	seated := true
	t.Cleanup(func() {
		if !seated {
			change(t, people.Admin, "GrantRole", team)
		}
	})
	change(t, people.Admin, "RevokeRole", team)
	seated = false
	answer, err = replay()
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("the child issued before the revocation, replayed at the hop after it: want permission_denied, got %d bytes, %v", len(answer), err)
	}
	if strings.Contains(string(answer), d.entry) {
		t.Errorf("the replayed child is answered the document")
	}
	t.Logf("the child (%d bytes), replayed at the hop after the revocation: %v", len(child[0]), err)

	change(t, people.Admin, "GrantRole", team)
	seated = true
	reads(t, people.User, d)
	_, err = replay()
	t.Logf("the same child, replayed after the role was granted back (not asserted: the host may or may not hold it stale): %v", err)
}
