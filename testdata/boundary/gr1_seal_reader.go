package solution

import (
	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"google.golang.org/protobuf/proto"
)

func readSeal(data []byte) error { var seal basev0.WorkSealV1; return proto.Unmarshal(data, &seal) }
