package solution

import "net/http"

type server struct{}

func (server) Routes() any { return http.NewServeMux() }
