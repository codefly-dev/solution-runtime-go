package solution

import (
	wire "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	pb "google.golang.org/protobuf/proto"
)

func readSeal(data []byte) error { return (pb.UnmarshalOptions{}).Unmarshal(data, &wire.WorkSealV1{}) }
