package solution

import (
	carrier "github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/protobuf/proto"
)

func readSeal(data []byte) error { var seal carrier.SealedValues; return proto.Unmarshal(data, &seal) }
