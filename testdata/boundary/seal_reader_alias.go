package solution

import (
	wire "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	pb "google.golang.org/protobuf/proto"
)

type local = wire.WorkSealV1
type alias = local

func readSeal(data []byte) error { var seal alias; return pb.Unmarshal(data, &seal) }
