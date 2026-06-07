BINARY := dist/shhx
GOFLAGS := -trimpath
BUILD_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X main.buildVersion=$(BUILD_VERSION)

.PHONY: fmt assets test test-e2e build run clean

fmt:
	gofmt -w main.go internal/app/security.go internal/app/security_test.go internal/app/server.go internal/app/server_test.go internal/app/static.go internal/app/static_test.go internal/room/hub.go internal/room/hub_test.go tools/minify-assets/main.go

assets:
	go run ./tools/minify-assets

test:
	$(MAKE) assets
	CGO_ENABLED=0 go test $(GOFLAGS) ./...

test-e2e:
	$(MAKE) assets
	npx playwright test

build:
	$(MAKE) assets
	mkdir -p dist
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) .

run:
	$(MAKE) assets
	CGO_ENABLED=0 go run $(GOFLAGS) .

clean:
	rm -rf dist
