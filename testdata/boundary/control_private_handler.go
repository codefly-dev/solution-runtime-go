package solution

import h "net/http"

type Server struct{ handler h.Handler }

func New() *Server            { return &Server{handler: h.NewServeMux()} }
func (*Server) Document() any { return "value" }
