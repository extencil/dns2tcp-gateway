.PHONY: build run test lint clean

BINARY := dns2tcp
PKG := ./cmd/dns2tcp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/ohmymex/dns2tcp-gateway/internal/version.Version=$(VERSION) \
	-X github.com/ohmymex/dns2tcp-gateway/internal/version.Commit=$(COMMIT) \
	-X github.com/ohmymex/dns2tcp-gateway/internal/version.BuildDate=$(BUILD_DATE)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

run: build
	GATEWAY_DNS_ADDR=:5354 GATEWAY_API_ADDR=:8080 LOG_LEVEL=debug ./$(BINARY)

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	go clean -testcache
