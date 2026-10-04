package solution

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

func readDocument(data []byte) error { return proto.Unmarshal(data, &emptypb.Empty{}) }
