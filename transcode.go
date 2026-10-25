package solution

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// --- Transcoded module calls ---
//
// The gateway reaches the host's own API over Connect, but a composed module
// only by the REST prefix the solution federates for it (/v1/<as>/*, see
// "Consumed-module federation" in the README). A module's generated client —
// gRPC or Connect — therefore cannot be pointed at the gateway: its procedure
// paths are not under that prefix. What a module does publish is the
// google.api.http binding of each RPC, carried in the generated descriptor.
// Transcoded speaks that binding, so a solution calls a composed module with
// the module's own generated request and response messages, and never builds a
// path, a query string or a wire struct by hand.

// DefaultTranscodedResponseLimit bounds a transcoded response body unless the
// call sets its own bound with MaxResponseBytes.
const DefaultTranscodedResponseLimit = 8 << 20

// TranscodeOption adjusts one Transcoded call.
type TranscodeOption func(*transcodeOptions)

type transcodeOptions struct {
	maxResponseBytes int64
}

// MaxResponseBytes bounds the response body of one call. A larger response is
// an error, never a truncated message.
func MaxResponseBytes(n int64) TranscodeOption {
	return func(o *transcodeOptions) { o.maxResponseBytes = n }
}

// Transcoded calls one RPC of a composed module through the gateway, over the
// module's HTTP/JSON binding.
//
// method is the RPC's full name as its generated code names it — the
// "/package.Service/Method" constant a gRPC or Connect stub declares — and is
// resolved in the global protobuf registry, so the module's generated package
// must be linked in. prefix is the REST prefix the solution consumes the module
// under ("/v1/documents"): the call uses the method's first HTTP binding whose
// path lies under it. The URL, the HTTP method, which request fields go into the
// path, the query or the body all come from the descriptor; the caller can name
// no path of its own. A method with no binding under prefix is refused before
// anything is sent.
//
// req and resp must be the method's input and output message types. The
// response is decoded with unknown fields discarded, so a module adding a
// field does not break its consumers. A non-2xx answer is a *GatewayError
// carrying the status, so a handler that returns it keeps an actionable status.
func (g *Gateway) Transcoded(ctx context.Context, prefix, method string, req, resp proto.Message, opts ...TranscodeOption) error {
	options := transcodeOptions{maxResponseBytes: DefaultTranscodedResponseLimit}
	for _, opt := range opts {
		opt(&options)
	}
	call, err := transcodeRequest(prefix, method, req, resp)
	if err != nil {
		return err
	}
	var body io.Reader
	if call.body != nil {
		body = bytes.NewReader(call.body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, call.verb, g.baseURL+call.path, body)
	if err != nil {
		return err
	}
	httpReq.Header.Set("accept", "application/json")
	if call.body != nil {
		httpReq.Header.Set("content-type", "application/json")
	}
	httpResp, err := g.HTTPClient().Do(httpReq)
	if err != nil {
		return fmt.Errorf("%s %s: %w", call.verb, call.template, err)
	}
	defer drainAndClose(httpResp)
	if httpResp.StatusCode < 200 || httpResp.StatusCode > 299 {
		return fmt.Errorf("%s %s: %w", call.verb, call.template, &GatewayError{StatusCode: httpResp.StatusCode})
	}
	raw, err := io.ReadAll(io.LimitReader(httpResp.Body, options.maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("%s %s: %w", call.verb, call.template, err)
	}
	if int64(len(raw)) > options.maxResponseBytes {
		return fmt.Errorf("%s %s: response exceeds %d bytes", call.verb, call.template, options.maxResponseBytes)
	}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw, resp); err != nil {
		return fmt.Errorf("%s %s: invalid %s: %w", call.verb, call.template, resp.ProtoReflect().Descriptor().FullName(), err)
	}
	return nil
}

// transcodedCall is one request, fully resolved from the descriptor.
type transcodedCall struct {
	verb     string
	template string // the binding's path template, for errors
	path     string // path and query, relative to the gateway
	body     []byte // nil when the binding carries no body
}

func transcodeRequest(prefix, method string, req, resp proto.Message) (transcodedCall, error) {
	if !cleanPrefix(prefix) {
		return transcodedCall{}, fmt.Errorf("transcoded call: prefix %q must be an absolute path such as /v1/<module>, with no trailing slash, dot segment, query or fragment", prefix)
	}
	md, err := methodDescriptor(method)
	if err != nil {
		return transcodedCall{}, err
	}
	if got, want := req.ProtoReflect().Descriptor().FullName(), md.Input().FullName(); got != want {
		return transcodedCall{}, fmt.Errorf("transcoded call %s: request is %s, want %s", md.FullName(), got, want)
	}
	if got, want := resp.ProtoReflect().Descriptor().FullName(), md.Output().FullName(); got != want {
		return transcodedCall{}, fmt.Errorf("transcoded call %s: response is %s, want %s", md.FullName(), got, want)
	}
	rule, verb, template, err := bindingUnder(md, prefix)
	if err != nil {
		return transcodedCall{}, err
	}
	msg := req.ProtoReflect()
	path, bound, err := expandTemplate(md, template, msg)
	if err != nil {
		return transcodedCall{}, err
	}
	call := transcodedCall{verb: verb, template: template}
	var queryExcluded protoreflect.FieldDescriptor
	switch rule.GetBody() {
	case "":
	case "*":
		call.body, err = protojson.Marshal(req)
		if err != nil {
			return transcodedCall{}, err
		}
		call.path = path
		return call, nil
	default:
		fd := msg.Descriptor().Fields().ByName(protoreflect.Name(rule.GetBody()))
		if fd == nil || fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
			return transcodedCall{}, fmt.Errorf("transcoded call %s: body %q is not a singular message field", md.FullName(), rule.GetBody())
		}
		call.body, err = protojson.Marshal(msg.Get(fd).Message().Interface())
		if err != nil {
			return transcodedCall{}, err
		}
		queryExcluded = fd
	}
	query := url.Values{}
	if err := encodeQuery(query, "", msg, bound, queryExcluded); err != nil {
		return transcodedCall{}, fmt.Errorf("transcoded call %s: %w", md.FullName(), err)
	}
	call.path = path
	if encoded := query.Encode(); encoded != "" {
		call.path += "?" + encoded
	}
	return call, nil
}

func cleanPrefix(prefix string) bool {
	if !strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") || strings.ContainsAny(prefix, "?#{}*:\\") {
		return false
	}
	for _, segment := range strings.Split(prefix[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// methodDescriptor resolves "/package.Service/Method" (or the dotted
// "package.Service.Method") in the global registry.
func methodDescriptor(method string) (protoreflect.MethodDescriptor, error) {
	name := strings.TrimPrefix(method, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[:i] + "." + name[i+1:]
	}
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, fmt.Errorf("transcoded call: method %q is not in the protobuf registry (is its generated package linked in?): %w", method, err)
	}
	md, ok := d.(protoreflect.MethodDescriptor)
	if !ok {
		return nil, fmt.Errorf("transcoded call: %q names a %T, not a method", method, d)
	}
	return md, nil
}

// bindingUnder returns the first HTTP binding of md — the primary rule, then
// its additional bindings in order — whose path lies under prefix.
func bindingUnder(md protoreflect.MethodDescriptor, prefix string) (*annotations.HttpRule, string, string, error) {
	primary, _ := proto.GetExtension(md.Options(), annotations.E_Http).(*annotations.HttpRule)
	if primary == nil {
		return nil, "", "", fmt.Errorf("transcoded call %s: the method declares no google.api.http binding", md.FullName())
	}
	rules := append([]*annotations.HttpRule{primary}, primary.GetAdditionalBindings()...)
	for _, rule := range rules {
		verb, template := ruleVerb(rule)
		if template == prefix || strings.HasPrefix(template, prefix+"/") || strings.HasPrefix(template, prefix+":") {
			return rule, verb, template, nil
		}
	}
	return nil, "", "", fmt.Errorf("transcoded call %s: no google.api.http binding under %s", md.FullName(), prefix)
}

func ruleVerb(rule *annotations.HttpRule) (string, string) {
	switch pattern := rule.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		return http.MethodGet, pattern.Get
	case *annotations.HttpRule_Post:
		return http.MethodPost, pattern.Post
	case *annotations.HttpRule_Put:
		return http.MethodPut, pattern.Put
	case *annotations.HttpRule_Delete:
		return http.MethodDelete, pattern.Delete
	case *annotations.HttpRule_Patch:
		return http.MethodPatch, pattern.Patch
	case *annotations.HttpRule_Custom:
		return pattern.Custom.GetKind(), pattern.Custom.GetPath()
	}
	return "", ""
}

// expandTemplate fills each {field} variable of template from msg. Only
// single-segment variables are supported ({field} and {field=*}); a
// multi-segment one is refused rather than guessed. Each value must be set and
// is path-escaped, so a value can never add a segment of its own.
func expandTemplate(md protoreflect.MethodDescriptor, template string, msg protoreflect.Message) (string, map[string]bool, error) {
	bound := map[string]bool{}
	var out strings.Builder
	rest := template
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			out.WriteString(rest)
			return out.String(), bound, nil
		}
		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			return "", nil, fmt.Errorf("transcoded call %s: malformed path template %q", md.FullName(), template)
		}
		out.WriteString(rest[:open])
		variable := rest[open+1 : open+end]
		field, pattern, hasPattern := strings.Cut(variable, "=")
		if hasPattern && pattern != "*" {
			return "", nil, fmt.Errorf("transcoded call %s: path variable {%s} is multi-segment, which is not supported", md.FullName(), variable)
		}
		value, err := scalarAt(msg, field)
		if err != nil {
			return "", nil, fmt.Errorf("transcoded call %s: path variable {%s}: %w", md.FullName(), field, err)
		}
		if value == "" {
			return "", nil, fmt.Errorf("transcoded call %s: path variable {%s} is empty", md.FullName(), field)
		}
		if value == "." || value == ".." {
			// Escaping leaves a dot segment as it is, and a normalizing hop
			// would resolve it to a different route.
			return "", nil, fmt.Errorf("transcoded call %s: path variable {%s} is a dot segment", md.FullName(), field)
		}
		out.WriteString(url.PathEscape(value))
		bound[field] = true
		rest = rest[open+end+1:]
	}
}

// scalarAt reads the scalar at a dotted field path of msg as its query/path
// text form.
func scalarAt(msg protoreflect.Message, path string) (string, error) {
	names := strings.Split(path, ".")
	for i, name := range names {
		fd := msg.Descriptor().Fields().ByName(protoreflect.Name(name))
		if fd == nil {
			return "", fmt.Errorf("no field %q in %s", name, msg.Descriptor().FullName())
		}
		if fd.IsList() || fd.IsMap() {
			return "", fmt.Errorf("field %q is repeated", name)
		}
		if i < len(names)-1 {
			if fd.Kind() != protoreflect.MessageKind {
				return "", fmt.Errorf("field %q is not a message", name)
			}
			msg = msg.Get(fd).Message()
			continue
		}
		return scalarText(fd, msg.Get(fd))
	}
	return "", fmt.Errorf("empty field path")
}

func scalarText(fd protoreflect.FieldDescriptor, v protoreflect.Value) (string, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return v.String(), nil
	case protoreflect.BoolKind:
		return strconv.FormatBool(v.Bool()), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return strconv.FormatInt(v.Int(), 10), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind, protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return strconv.FormatUint(v.Uint(), 10), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return strconv.FormatFloat(v.Float(), 'g', -1, 64), nil
	case protoreflect.BytesKind:
		return base64.URLEncoding.EncodeToString(v.Bytes()), nil
	case protoreflect.EnumKind:
		if ev := fd.Enum().Values().ByNumber(v.Enum()); ev != nil {
			return string(ev.Name()), nil
		}
		return strconv.FormatInt(int64(v.Enum()), 10), nil
	}
	return "", fmt.Errorf("field %q of kind %s has no query form", fd.Name(), fd.Kind())
}

// encodeQuery adds every populated field of msg not bound by the path (or sent
// as the body) as query parameters, by proto field name — the form the
// HTTP/JSON transcoder reads. Nested messages flatten to dotted names; repeated
// scalars repeat the key. A map or a repeated message has no query form and is
// refused rather than silently dropped.
func encodeQuery(query url.Values, parent string, msg protoreflect.Message, bound map[string]bool, excluded protoreflect.FieldDescriptor) error {
	var err error
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if excluded != nil && fd == excluded {
			return true
		}
		name := string(fd.Name())
		if parent != "" {
			name = parent + "." + name
		}
		if bound[name] {
			return true
		}
		switch {
		case fd.IsMap():
			err = fmt.Errorf("map field %q has no query form", name)
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
				err = fmt.Errorf("repeated message field %q has no query form", name)
				break
			}
			list := v.List()
			for i := 0; i < list.Len() && err == nil; i++ {
				var text string
				if text, err = scalarText(fd, list.Get(i)); err == nil {
					query.Add(name, text)
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			if strings.HasPrefix(string(fd.Message().FullName()), "google.protobuf.") {
				// A well-known type has a JSON form of its own (a timestamp is
				// RFC 3339 text), which flattening its fields would not produce.
				err = fmt.Errorf("well-known type field %q has no query form here; send it in a body", name)
				break
			}
			err = encodeQuery(query, name, v.Message(), bound, nil)
		default:
			var text string
			if text, err = scalarText(fd, v); err == nil {
				query.Set(name, text)
			}
		}
		return err == nil
	})
	return err
}
