package solution

import h "net/http"

type local = h.Handler
type Routes struct{ Handler local }
