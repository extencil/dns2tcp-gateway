.PHONY: build run test lint clean

BINARY := gateway
PKG := ./cmd/gateway

build:
	go build -o $(BINARY) $(PKG)

run: build
	GATEWAY_DNS_ADDR=:5354 GATEWAY_API_ADDR=:8080 LOG_LEVEL=debug ./$(BINARY)

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY)
	go clean -testcache
