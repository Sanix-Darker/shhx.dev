BINARY := dist/shhx
GOFLAGS := -trimpath
LDFLAGS := -s -w -buildid=

.PHONY: fmt assets test build run clean

fmt:
	gofmt -w main.go internal/app/security.go internal/app/server.go internal/app/server_test.go internal/room/hub.go internal/room/hub_test.go tools/minify-assets/main.go

assets:
	go run ./tools/minify-assets

test:
	$(MAKE) assets
	CGO_ENABLED=0 go test $(GOFLAGS) ./...

build:
	$(MAKE) assets
	mkdir -p dist
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) .

run:
	$(MAKE) assets
	CGO_ENABLED=0 go run $(GOFLAGS) .

clean:
	rm -rf dist
