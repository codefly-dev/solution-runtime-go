package solution

import "net/http"

type local = http.Handler
type second = local
type server struct{}

func (server) Routes() second { return http.NewServeMux() }
