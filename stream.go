package solution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// --- Streamed methods ---
//
// A consumed module's server-streaming method passes through as a Connect
// server-streaming procedure, relayed as a gRPC stream to the module's own
// procedure through the hop, under the same authority as a unary one: the
// child Work Context issued for that method, and the declared response fields
// applied to every message before it reaches the page.
//
// Every stream is bounded: the module's first message by the method's Timeout
// (a module that accepts the stream and sends nothing is cut off then, not at
// the end of the whole duration), its duration by the method's
// MaxStreamDuration, and each message by MaxStreamMessageBytes. The page disconnecting cancels the
// module's stream at once; the module ending it with a status ends the page's
// with the same code, by moduleRefusal's rule.

const (
	// DefaultStreamDuration bounds a stream unless the method declares its own.
	DefaultStreamDuration = 5 * time.Minute
	// MaxStreamDurationLimit is the longest stream a method may declare.
	MaxStreamDurationLimit = 30 * time.Minute
	// DefaultStreamMessageLimit bounds one streamed message unless the method
	// declares its own.
	DefaultStreamMessageLimit = 1 << 20
)

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

// relayStream answers one streamed call as the viewer: the child Work Context
// issued for the method, the module's stream over gRPC, and only the declared
// response fields of each message.
func (s *Server) relayStream(ctx context.Context, route passthroughRoute, req *connect.Request[dynamicpb.Message], stream *connect.ServerStream[dynamicpb.Message]) error {
	// The whole stream, from the call to its last message, is bounded; the
	// page going away cancels it (ctx is the page's request).
	ctx, cancel := context.WithTimeout(ctx, route.streamDuration())
	defer cancel()
	issue, cancelIssue := context.WithTimeout(ctx, route.timeout())
	relay, token, err := s.asTheViewer(issue, route, req)
	cancelIssue()
	if err != nil {
		return err
	}
	// The module's first answer is bounded like a unary call (route.timeout):
	// until it arrives, a timer cancels the stream, so a module that accepts
	// it and sends nothing holds the page's request, a goroutine and an HTTP/2
	// stream for that long and no longer.
	streaming, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	var late atomic.Bool
	firstAnswer := time.AfterFunc(route.timeout(), func() { late.Store(true); cancelStream() })
	defer firstAnswer.Stop()
	calling := grpcmetadata.AppendToOutgoingContext(streaming, WorkContextHeader, token)
	module, err := relay.conn.NewStream(calling, &grpc.StreamDesc{StreamName: string(route.md.Name()), ServerStreams: true}, route.procedure(),
		grpc.MaxCallRecvMsgSize(int(route.streamMessageLimit())))
	if err == nil {
		err = module.SendMsg(req.Msg)
	}
	if err == nil {
		err = module.CloseSend()
	}
	for err == nil {
		out := dynamicpb.NewMessage(route.md.Output())
		err = module.RecvMsg(out)
		firstAnswer.Stop()
		if err != nil || late.Load() {
			break
		}
		if sendErr := stream.Send(route.answer(out)); sendErr != nil {
			// The page went away, or its connection broke: nothing to tell it.
			return sendErr
		}
	}
	switch {
	case late.Load():
		return connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("the module did not start its stream within %s", route.timeout()))
	case errors.Is(err, io.EOF):
		return nil
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("the stream reached its declared duration (%s)", route.streamDuration()))
	}
	return s.moduleRefusal(route, err)
}
