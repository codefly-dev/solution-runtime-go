package solution

import h "net/http"

type server struct{}

func (server) Routes() h.Handler { return h.NewServeMux() }
