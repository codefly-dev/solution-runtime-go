package solution

import (
	"time"

	kit "github.com/codefly-dev/core/workcontext"
)

func fixtures() { _, _ = kit.Fixtures(time.Now()) }
