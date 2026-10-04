package solution

import h "net/http"

func Routes() func(h.ResponseWriter, *h.Request) { return func(h.ResponseWriter, *h.Request) {} }
