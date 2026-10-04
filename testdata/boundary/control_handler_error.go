package solution

import "net/http"

func Validate() error              { _, err := build(); return err }
func build() (http.Handler, error) { return http.NewServeMux(), nil }
