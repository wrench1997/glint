OS = $(shell go env GOOS)
ARCH = ${shell go env GOARCH}
VERSION = $(shell git describe --tags --always)

.PHONY: build
# complate current machine binary executable file
build:
	rm -rf bin && mkdir -p bin/${OS}-${ARCH} && go build -ldflags "-X main.Version=$(VERSION)" -o ./bin/${OS}-${ARCH} ./...

.PHONY: build_all
# complate [darwin_arm64,darwin_amd64, linux_arm64, linux_amd64] machine binary executable file
build_all:
	rm -rf bin && mkdir bin bin/linux-amd64 bin/linux-arm64 bin/darwin-amd64 bin/darwin-arm64 \
	&& CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=$(VERSION)" -o ./bin/darwin-arm64/ ./... \
	&& CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o ./bin/darwin-amd64/ ./... \
	&& CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=$(VERSION)" -o ./bin/linux-arm64/ ./... \
	&& CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -o ./bin/linux-amd64/ ./...

# show help
help:
	@echo ''
	@echo 'Usage:'
	@echo ' make [target]'
	@echo ''
	@echo 'Targets:'
	@awk '/^[a-zA-Z\-\_0-9]+:/ { \
	helpMessage = match(lastLine, /^# (.*)/); \
		if (helpMessage) { \
			helpCommand = substr($$1, 0, index($$1, ":")-1); \
			helpMessage = substr(lastLine, RSTART + 2, RLENGTH); \
			printf "\033[36m%-22s\033[0m %s\n", helpCommand,helpMessage; \
		} \
	} \
	{ lastLine = $$0 }' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help