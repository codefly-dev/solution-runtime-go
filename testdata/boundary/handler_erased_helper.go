package solution

import "net/http"

func Routes() any { return erased() }
func erased() any { var value any = http.NewServeMux(); return value }
