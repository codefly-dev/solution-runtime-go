package solution

import (
	wire "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	pb "google.golang.org/protobuf/proto"
)

func readSeal(data []byte) error {
	var target pb.Message = &wire.WorkSealV1{}
	decode := pb.Unmarshal
	return decode(data, target)
}
