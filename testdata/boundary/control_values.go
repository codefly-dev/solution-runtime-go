package solution

func Document() any           { return map[string]string{"version": "v1"} }
func Callback() func() string { return func() string { return "value" } }
