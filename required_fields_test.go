package solution

import (
	"bytes"
	"encoding/json"
	"github.com/codefly-dev/solution-runtime-go/internal/requestschematest/first"
	"github.com/codefly-dev/solution-runtime-go/internal/requestschematest/second"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/api/annotations"
)

type requiredRequest struct {
	RecordID     string `json:"recordId"`
	Revision     string `json:"revision,omitempty"`
	TypeRevision string `json:"typeRevision"`
	Optional     string `json:"optional,omitempty"`
	DefaultName  string
	Ignored      string `json:"-"`
	hidden       string
	Child        *requiredRequest `json:"child,omitempty"`
}
type requiredEmbedded struct{ requiredRequest }
type requiredCollision struct {
	A string
	B string `json:"A"`
}
type requiredInvalidTag struct {
	A string `json:"bad\\name"`
}
type requiredStringTag struct {
	A int `json:"a,string"`
}
type requiredDashTag struct {
	A string `json:"-,omitempty"`
}
type requiredCustom struct {
	A string `json:"a"`
}

func (*requiredCustom) UnmarshalJSON([]byte) error { return nil }

type requiredCustomText struct {
	A string `json:"a"`
}

func (*requiredCustomText) UnmarshalText([]byte) error { return nil }

func requiredOperation(request any) Operation {
	op := documentedOperations()[0]
	op.Path = "/review"
	op.Method = "post"
	op.Request = request
	op.Response = requiredRequest{}
	return op
}
func requiredArtifact(t *testing.T, ops ...Operation) []byte {
	t.Helper()
	raw, err := New(Manifest{ID: "test"}).Operations(ops...).InterfaceArtifact("", InterfaceInfo{Version: "1", OperationPrefix: "Test"})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestRequiredFieldsAreOperationLocal(t *testing.T) {
	names := []string{"recordId", "revision", "typeRevision", "DefaultName"}
	wrapped := RequiredFields(&requiredRequest{}, names...)
	names[0] = "changed-by-caller"
	required := requiredOperation(wrapped)
	optional := requiredOperation(requiredRequest{})
	optional.Path = "/optional"
	for _, ops := range [][]Operation{{required, optional}, {optional, required}} {
		raw := requiredArtifact(t, ops...)
		if !bytes.Equal(raw, requiredArtifact(t, ops...)) {
			t.Fatal("unstable artifact")
		}
		var doc struct {
			Paths map[string]map[string]struct {
				Parameters []struct{ Schema map[string]any }
				Responses  map[string]struct{ Schema map[string]any }
			}
			Definitions map[string]map[string]any
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		ref := doc.Paths["/review"]["post"].Parameters[0].Schema["$ref"].(string)
		root := doc.Definitions[strings.TrimPrefix(ref, "#/definitions/")]
		if root["$ref"] != nil || !reflect.DeepEqual(root["required"], []any{"recordId", "revision", "typeRevision", "DefaultName"}) {
			t.Fatalf("root = %v", root)
		}
		definition := doc.Definitions["RequiredRequest"]
		if definition["required"] != nil {
			t.Fatal("shared definition changed")
		}
		if doc.Paths["/optional"]["post"].Parameters[0].Schema["$ref"] != "#/definitions/RequiredRequest" {
			t.Fatal("other request changed")
		}
		if doc.Paths["/review"]["post"].Responses["200"].Schema["$ref"] != "#/definitions/RequiredRequest" {
			t.Fatal("response changed")
		}
		if doc.Definitions[requiredRequestDefinition(required)+".RequiredRequest"]["required"] != nil {
			t.Fatal("recursive definition became required")
		}
		child := root["properties"].(map[string]any)["child"].(map[string]any)
		if child["$ref"] != "#/definitions/"+requiredRequestDefinition(required)+".RequiredRequest" {
			t.Fatal("recursive occurrence did not use its isolated optional definition")
		}
	}
}
func TestRequiredFieldsEmptyLeavesExactArtifactUnchanged(t *testing.T) {
	for _, request := range []any{nil, requiredRequest{}, (*requiredRequest)(nil), Message[*annotations.HttpRule]{}} {
		baseline := requiredArtifact(t, requiredOperation(request))
		for _, names := range [][]string{nil, {}} {
			actual := requiredArtifact(t, requiredOperation(RequiredFields(request, names...)))
			if !bytes.Equal(baseline, actual) {
				t.Fatal("empty declaration changed artifact")
			}
		}
	}
}
func TestRequiredFieldsRefuseInvalidDeclarationsAtGenerationAndBoot(t *testing.T) {
	tests := []struct {
		name    string
		request any
		fields  []string
		want    string
	}{
		{"blank", requiredRequest{}, []string{" "}, `property " " is blank`},
		{"duplicate", requiredRequest{}, []string{"recordId", "recordId"}, `property "recordId" is duplicated`},
		{"misspelling", requiredRequest{}, []string{"recordID"}, `property "recordID" is not emitted`},
		{"ignored", requiredRequest{}, []string{"Ignored"}, `property "Ignored" is not emitted`},
		{"unexported", requiredRequest{}, []string{"hidden"}, `property "hidden" is not emitted`},
		{"nil", nil, []string{"a"}, "not nil"},
		{"typed nil", (*requiredRequest)(nil), []string{"a"}, "non-nil request pointer"},
		{"scalar", "", []string{"a"}, "ordinary struct"},
		{"array", [1]string{}, []string{"a"}, "ordinary struct"},
		{"map", map[string]string{}, []string{"a"}, "ordinary struct"},
		{"anonymous", struct{ A string }{}, []string{"A"}, "ordinary struct"},
		{"embedded", requiredEmbedded{}, []string{"recordId"}, "is embedded"},
		{"collision", requiredCollision{}, []string{"A"}, `colliding JSON property "A"`},
		{"tag", requiredInvalidTag{}, []string{"a"}, "invalid JSON name"},
		{"string tag", requiredStringTag{}, []string{"a"}, "unsupported JSON tag"},
		{"dash tag", requiredDashTag{}, []string{"-"}, "unsupported JSON tag"},
		{"custom", requiredCustom{}, []string{"a"}, "custom JSON/text codec"},
		{"custom text", requiredCustomText{}, []string{"a"}, "custom JSON/text codec"},
		{"proto", Message[*annotations.HttpRule]{}, []string{"selector"}, "ordinary struct"},
		{"nested wrapper", RequiredFields(requiredRequest{}, "recordId"), []string{"recordId"}, "cannot wrap another RequiredRequest"},
		{"empty nested wrapper", RequiredFields(requiredRequest{}, "recordId"), nil, "cannot wrap another RequiredRequest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := requiredOperation(RequiredFields(tt.request, tt.fields...))
			_, artifactErr := New(Manifest{ID: "test"}).Operations(op).InterfaceArtifact("", InterfaceInfo{Version: "1"})
			_, bootErr := New(Manifest{ID: "test"}).Operations(op).operationTable()
			for _, err := range []error{artifactErr, bootErr} {
				if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "operation POST /review") {
					t.Fatalf("error = %v; want %s", err, tt.want)
				}
			}
			if artifactErr.Error() != bootErr.Error() {
				t.Fatal("generation and boot disagree")
			}
		})
	}
	op := requiredOperation(requiredRequest{})
	op.Response = RequiredFields(requiredRequest{}, "recordId")
	if _, err := InterfaceDocument(InterfaceInfo{}, []Operation{op}); err == nil || !strings.Contains(err.Error(), "not Response") {
		t.Fatalf("response wrapper: %v", err)
	}
}

// Error deliberately collides with the document's built-in failure definition.
type Error struct {
	Error string `json:"error"`
	Extra string `json:"extra"`
}
type requestWithTime struct {
	Key string    `json:"key"`
	At  time.Time `json:"at"`
}
type requestWithCodec struct {
	Key    string           `json:"key"`
	Nested []requiredCustom `json:"nested"`
}
type requestWithTextCodec struct {
	Key    string                         `json:"key"`
	Nested map[string]*requiredCustomText `json:"nested"`
}
type requestWithBytes struct {
	Key   string `json:"key"`
	Bytes []byte `json:"bytes"`
}
type requestWithInterface struct {
	Key string `json:"key"`
	Any any    `json:"any"`
}
type requestWithCollision struct {
	Key string        `json:"key"`
	A   first.Shared  `json:"a"`
	B   second.Shared `json:"b"`
}
type requestCollections struct {
	Key     string                  `json:"key"`
	Pointer *string                 `json:"pointer,omitempty"`
	Slice   []first.Shared          `json:"slice,omitempty"`
	Map     map[string]first.Shared `json:"map,omitempty"`
	Array   [2]int                  `json:"array"`
	Ref     string                  `json:"$ref"`
}

func TestRequiredFieldsIsolateDefinitionIdentity(t *testing.T) {
	for _, request := range []struct {
		value      any
		required   string
		properties []string
	}{
		{Error{}, "error", []string{"error", "extra"}},
		{first.Shared{}, "first", []string{"first"}},
	} {
		marked := requiredOperation(RequiredFields(request.value, request.required))
		marked.Response = second.Shared{}
		other := requiredOperation(second.Shared{})
		other.Path = "/other"
		other.Response = second.Shared{}
		for _, ops := range [][]Operation{{marked, other}, {other, marked}} {
			if _, err := New(Manifest{ID: "test"}).Operations(ops...).operationTable(); err != nil {
				t.Fatal(err)
			}
			raw := requiredArtifact(t, ops...)
			var doc struct{ Definitions map[string]map[string]any }
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			root := doc.Definitions[requiredRequestDefinition(marked)]
			properties := root["properties"].(map[string]any)
			if len(properties) != len(request.properties) {
				t.Fatalf("properties = %v", properties)
			}
			for _, name := range request.properties {
				if properties[name] == nil {
					t.Fatalf("missing %s", name)
				}
			}
			if len(doc.Definitions["Error"]["properties"].(map[string]any)) != 1 {
				t.Fatal("failure definition changed")
			}
			if doc.Definitions["Shared"]["properties"].(map[string]any)["second"] == nil {
				t.Fatal("control response/request changed")
			}
		}
	}
}

func TestRequiredFieldsCheckTheReachableWireShape(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value any
		want  string
	}{
		{"time", requestWithTime{}, "request.at (time.Time) has a custom JSON/text codec"},
		{"JSON codec in slice", requestWithCodec{}, "request.nested[]"},
		{"text codec in map pointer", requestWithTextCodec{}, "request.nested{}"},
		{"bytes", requestWithBytes{}, "request.bytes is a byte slice"},
		{"dynamic interface", requestWithInterface{}, "request.any has unsupported type"},
		{"colliding reachable names", requestWithCollision{}, "collide at definition"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			op := requiredOperation(RequiredFields(tt.value, "key"))
			_, generationErr := InterfaceDocument(InterfaceInfo{}, []Operation{op})
			_, bootErr := New(Manifest{ID: "test"}).Operations(op).operationTable()
			if generationErr == nil || bootErr == nil || generationErr.Error() != bootErr.Error() || !strings.Contains(generationErr.Error(), tt.want) {
				t.Fatalf("generation %v, boot %v; want %q", generationErr, bootErr, tt.want)
			}
			// Unwrapped declarations deliberately retain their previous behavior.
			// Byte slices already panic in the legacy generator (uint8 unsupported).
			if tt.name == "bytes" {
				return
			}
			op.Request = tt.value
			if _, err := InterfaceDocument(InterfaceInfo{}, []Operation{op}); err != nil {
				t.Fatal(err)
			}
		})
	}
	value := "present"
	request := requestCollections{Key: "key", Pointer: &value, Slice: []first.Shared{{First: "a"}}, Map: map[string]first.Shared{"a": {First: "b"}}, Array: [2]int{1, 2}, Ref: "literal property"}
	op := requiredOperation(RequiredFields(request, "key"))
	if _, err := New(Manifest{ID: "test"}).Operations(op).operationTable(); err != nil {
		t.Fatal(err)
	}
	raw := requiredArtifact(t, op)
	var doc struct{ Definitions map[string]map[string]any }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := doc.Definitions[requiredRequestDefinition(op)]
	properties := root["properties"].(map[string]any)
	for _, name := range []string{"pointer", "slice", "map", "array", "$ref"} {
		if properties[name] == nil {
			t.Fatalf("missing %s", name)
		}
	}
	if properties["pointer"].(map[string]any)["type"] != "string" || properties["$ref"].(map[string]any)["type"] != "string" {
		t.Fatal("pointer or literal $ref property misdescribed")
	}
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var valueOnWire map[string]any
	if err = json.Unmarshal(wire, &valueOnWire); err != nil {
		t.Fatal(err)
	}
	definitions := map[string]any{}
	for name, definition := range doc.Definitions {
		definitions[name] = definition
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("request.json", map[string]any{"$ref": "#/definitions/" + requiredRequestDefinition(op), "definitions": definitions}); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("request.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = schema.Validate(valueOnWire); err != nil {
		t.Fatalf("supported wire value refused: %v", err)
	}
	valueOnWire["pointer"] = nil
	if err = schema.Validate(valueOnWire); err == nil {
		t.Fatal("non-null input subset unexpectedly accepted null")
	}
	delete(valueOnWire, "pointer")
	if err = schema.Validate(valueOnWire); err != nil {
		t.Fatalf("optional pointer omission refused: %v", err)
	}
	if request.Pointer == nil || *request.Pointer != "present" {
		t.Fatal("non-null pointer wire value differs")
	}
	// This API deliberately retains the generator's non-null input subset;
	// nil pointers/collections can encode null, which that schema does not admit.
	nilWire, err := json.Marshal(struct {
		P *string `json:"p"`
	}{})
	if err != nil || string(nilWire) != `{"p":null}` {
		t.Fatalf("nil pointer wire=%s, %v", nilWire, err)
	}
}
