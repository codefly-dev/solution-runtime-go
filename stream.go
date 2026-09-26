package solution

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// --- Streamed methods ---
//
// A consumed module's server-streaming method passes through as a Connect
// server-streaming procedure, under the same authority as a unary one: the
// viewer's Work Context minted for that method (or the bearer alone, for a
// ViewerBearer module), and the declared response fields applied to every
// message before it reaches the page.
//
// The module answers the method's google.api.http binding the way grpc-gateway
// answers a server-streaming method: a 2xx response, content type
// application/x-ndjson (application/json is accepted too), whose body is one
// JSON object per line, flushed as each is ready:
//
//	{"result": <the message, in protobuf JSON>}
//	{"error": {"code": <google.rpc.Code number>, "message": "<text>"}}
//
// Blank lines are ignored (a module may send them to keep an idle connection
// alive). An error line ends the stream with that code and message; the end of
// the body ends it normally. A non-2xx answer before the stream starts is the
// module's refusal, relayed like a unary one.
//
// Every stream is bounded: its duration by the method's MaxStreamDuration, and
// each message by MaxStreamMessageBytes. The page disconnecting cancels the
// module request at once.

const (
	// DefaultStreamDuration bounds a stream unless the method declares its own.
	DefaultStreamDuration = 5 * time.Minute
	// MaxStreamDurationLimit is the longest stream a method may declare.
	MaxStreamDurationLimit = 30 * time.Minute
	// DefaultStreamMessageLimit bounds one streamed message unless the method
	// declares its own.
	DefaultStreamMessageLimit = 1 << 20
)

// ErrStreamMessageTooLarge is a streamed message over its declared bound.
var ErrStreamMessageTooLarge = errors.New("a streamed message exceeds its bound")

// StreamError is an error line a module's stream ended with.
type StreamError struct {
	Code    int32
	Message string
}

func (e *StreamError) Error() string {
	return fmt.Sprintf("the module's stream ended with code %d: %s", e.Code, e.Message)
}

// checkStreamBounds refuses stream bounds on a unary method (they would never
// apply) and bounds a streaming method cannot keep.
func checkStreamBounds(md protoreflect.MethodDescriptor, method ConsumedMethod) error {
	if !md.IsStreamingServer() {
		if method.MaxStreamDuration != 0 || method.MaxStreamMessageBytes != 0 {
			return fmt.Errorf("%s is unary, but declares stream bounds", md.FullName())
		}
		return nil
	}
	switch {
	case method.MaxStreamDuration < 0 || method.MaxStreamDuration > MaxStreamDurationLimit:
		return fmt.Errorf("%s: MaxStreamDuration %s is outside (0, %s]", md.FullName(), method.MaxStreamDuration, MaxStreamDurationLimit)
	case method.MaxStreamMessageBytes < 0:
		return fmt.Errorf("%s: MaxStreamMessageBytes %d is negative", md.FullName(), method.MaxStreamMessageBytes)
	case method.MaxResponseBytes != 0:
		return fmt.Errorf("%s streams: bound each message with MaxStreamMessageBytes, not MaxResponseBytes", md.FullName())
	}
	return nil
}

func (r passthroughRoute) streamDuration() time.Duration {
	if r.method.MaxStreamDuration > 0 {
		return r.method.MaxStreamDuration
	}
	return DefaultStreamDuration
}

func (r passthroughRoute) streamMessageLimit() int64 {
	if r.method.MaxStreamMessageBytes > 0 {
		return r.method.MaxStreamMessageBytes
	}
	return DefaultStreamMessageLimit
}

// forwardStream answers one streamed call as the viewer: the declared
// authority, the module's stream over its binding, and only the declared
// response fields of each message.
func (s *Server) forwardStream(ctx context.Context, route passthroughRoute, req *connect.Request[dynamicpb.Message], stream *connect.ServerStream[dynamicpb.Message]) error {
	if req.Header().Get("authorization") == "" {
		return connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer"))
	}
	// The whole stream, from the call to its last message, is bounded; the
	// page going away cancels it (ctx is the page's request).
	ctx, cancel := context.WithTimeout(ctx, route.streamDuration())
	defer cancel()
	timeout := route.method.Timeout
	if timeout <= 0 {
		timeout = DefaultPassthroughTimeout
	}
	setup, cancelSetup := context.WithTimeout(ctx, timeout)
	gw, err := s.authorize(setup, route, req.Header(), req.Msg)
	cancelSetup()
	if err != nil {
		return err
	}
	err = gw.TranscodedStream(ctx, "/v1/"+route.module.As, route.method.Name, req.Msg, func() proto.Message {
		return dynamicpb.NewMessage(route.md.Output())
	}, func(msg proto.Message) error {
		out := msg.(*dynamicpb.Message)
		if !route.method.WholeResponse {
			out = Apply(route.method.Response, out)
		}
		return stream.Send(out)
	}, StreamFirstAnswerWithin(timeout), MaxStreamMessageBytes(route.streamMessageLimit()))
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
		return connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("the stream reached its declared duration (%s)", route.streamDuration()))
	}
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return err
	}
	return relayedError(err)
}

// StreamOption adjusts one TranscodedStream call.
type StreamOption func(*streamOptions)

type streamOptions struct {
	maxMessageBytes int64
	firstAnswer     time.Duration
}

// MaxStreamMessageBytes bounds each message of the stream. A larger one ends
// the stream with ErrStreamMessageTooLarge, never a truncated message.
func MaxStreamMessageBytes(n int64) StreamOption {
	return func(o *streamOptions) { o.maxMessageBytes = n }
}

// StreamFirstAnswerWithin bounds how long the module takes to answer (its
// status line and headers); the stream after that is bounded by ctx.
func StreamFirstAnswerWithin(d time.Duration) StreamOption {
	return func(o *streamOptions) { o.firstAnswer = d }
}

// TranscodedStream calls one server-streaming RPC of a composed module through
// the gateway, over the module's HTTP/JSON binding, and hands each streamed
// message to each in order: newMsg makes the (empty) message each line decodes
// into. It returns when the stream ends: nil at the end of the body, a
// *StreamError for an error line, the error each returned, or ctx's error. See
// "Streamed methods" for the wire.
func (g *Gateway) TranscodedStream(ctx context.Context, prefix, method string, req proto.Message, newMsg func() proto.Message, each func(proto.Message) error, opts ...StreamOption) error {
	options := streamOptions{maxMessageBytes: DefaultStreamMessageLimit}
	for _, opt := range opts {
		opt(&options)
	}
	md, err := methodDescriptor(method)
	if err != nil {
		return err
	}
	if !md.IsStreamingServer() || md.IsStreamingClient() {
		return fmt.Errorf("transcoded stream %s: the method is not server-streaming", md.FullName())
	}
	call, err := transcodeRequest(prefix, method, req, newMsg())
	if err != nil {
		return err
	}
	var body io.Reader
	if call.body != nil {
		body = bytes.NewReader(call.body)
	}
	// The module request lives as long as the stream; it is cancelled when the
	// stream ends for any reason, the page going away included.
	reqCtx, cancelReq := context.WithCancel(ctx)
	defer cancelReq()
	httpReq, err := http.NewRequestWithContext(reqCtx, call.verb, g.baseURL+call.path, body)
	if err != nil {
		return err
	}
	httpReq.Header.Set("accept", "application/x-ndjson, application/json")
	if call.body != nil {
		httpReq.Header.Set("content-type", "application/json")
	}
	var late atomic.Bool
	if options.firstAnswer > 0 {
		// A module that never starts its stream is abandoned; the stream
		// itself, once started, is bounded only by ctx.
		timer := time.AfterFunc(options.firstAnswer, func() { late.Store(true); cancelReq() })
		defer timer.Stop()
		httpResp, err := g.HTTPClient().Do(httpReq)
		timer.Stop()
		if err != nil {
			if late.Load() && ctx.Err() == nil {
				return fmt.Errorf("%s %s: the module did not start its stream within %s: %w", call.verb, call.template, options.firstAnswer, context.DeadlineExceeded)
			}
			return fmt.Errorf("%s %s: %w", call.verb, call.template, err)
		}
		return readStream(ctx, call, httpResp, options, newMsg, each)
	}
	httpResp, err := g.HTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("%s %s: %w", call.verb, call.template, err)
	}
	return readStream(ctx, call, httpResp, options, newMsg, each)
}

// readStream reads a started stream to its end.
func readStream(ctx context.Context, call transcodedCall, httpResp *http.Response, options streamOptions, newMsg func() proto.Message, each func(proto.Message) error) error {
	// Closed, never drained: a stream has no end to drain to, and the
	// request's context cancellation has already stopped it on the way out.
	defer httpResp.Body.Close()
	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		detail, _ := io.ReadAll(io.LimitReader(httpResp.Body, gatewayErrorDetailLimit))
		return fmt.Errorf("%s %s: %w", call.verb, call.template, &GatewayError{StatusCode: httpResp.StatusCode, detail: detail})
	}
	if media, _, err := mime.ParseMediaType(httpResp.Header.Get("content-type")); err != nil || (media != "application/x-ndjson" && media != "application/json") {
		return fmt.Errorf("%s %s: the module answered %q, not a newline-delimited JSON stream", call.verb, call.template, httpResp.Header.Get("content-type"))
	}
	// A line is its message plus the envelope around it.
	reader := bufio.NewReaderSize(httpResp.Body, 64<<10)
	lineLimit := options.maxMessageBytes + 64
	for {
		line, err := readLine(reader, lineLimit)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, ErrStreamMessageTooLarge) {
				return err
			}
			return fmt.Errorf("%s %s: %w", call.verb, call.template, err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var envelope struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int32  `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return fmt.Errorf("%s %s: an undecodable line in the stream: %w", call.verb, call.template, err)
		}
		switch {
		case envelope.Error != nil:
			return &StreamError{Code: envelope.Error.Code, Message: envelope.Error.Message}
		case envelope.Result == nil:
			return fmt.Errorf("%s %s: a line in the stream carries neither a result nor an error", call.verb, call.template)
		case int64(len(envelope.Result)) > options.maxMessageBytes:
			return ErrStreamMessageTooLarge
		}
		msg := newMsg()
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(envelope.Result, msg); err != nil {
			return fmt.Errorf("%s %s: invalid %s in the stream: %w", call.verb, call.template, msg.ProtoReflect().Descriptor().FullName(), err)
		}
		if err := each(msg); err != nil {
			return err
		}
	}
}

// readLine reads one line, refusing one longer than limit rather than
// buffering it whole.
func readLine(r *bufio.Reader, limit int64) ([]byte, error) {
	var line []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return line, nil
			}
			return nil, err
		}
		line = append(line, chunk...)
		if int64(len(line)) > limit {
			return nil, ErrStreamMessageTooLarge
		}
		if !isPrefix {
			return line, nil
		}
	}
}
