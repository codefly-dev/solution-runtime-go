comma := ,

.PHONY: verify
verify: export GOWORK := off
verify: export GOPRIVATE := $(if $(GOPRIVATE),$(GOPRIVATE)$(comma))github.com/codefly-dev/*,github.com/obin-ai/*
verify:
	go mod download
	go mod verify
	go test -race ./... -count=1 -timeout=5m
	go vet ./...
	test -z "$$(gofmt -l .)"
