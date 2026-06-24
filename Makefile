BINARY := mixo

.DEFAULT_GOAL := run
.PHONY: fmt vet lint tidy test build run clean mocks ent generate

## fmt: Format all Go source files using gofmt
fmt:
	go fmt ./...

## vet: Run static analysis to catch common Go mistakes
vet:
	go vet ./...

## lint: Run fmt, vet, golangci-lint, and govulncheck
lint: fmt vet
	golangci-lint run ./... 
	govulncheck ./...


## tidy: Add missing and remove unused module dependencies
tidy:
	go mod tidy

## test: Run all tests
test:
	go test ./... -count=1 -race

## build: Compile the binary
build:
	go build -race -o $(BINARY) ./cmd/

## run: Run the application
run:
	go run ./cmd/

## clean: Remove compiled binary and build cache
clean:
	go clean
	rm -f $(BINARY)
## mocks: Generate mock files
mocks:
	go generate ./internal/...

## ent: Generate ent files
ent:
	go generate ./ent

## generate: Generate all files
generate: ent mocks
