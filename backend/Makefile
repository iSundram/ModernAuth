# ModernAuth Makefile

# Variables
BINARY_NAME=auth-server
CMD_PATH=./cmd/auth-server/main.go
DOCKER_COMPOSE=docker-compose.yml

# Load environment variables if .env exists
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

.PHONY: all build run test clean docker-up docker-down migrate-up migrate-down lint help

all: build

## build: Build the binary
build:
	go build -o bin/$(BINARY_NAME) $(CMD_PATH)

## run: Build and run the server
run: build
	./bin/$(BINARY_NAME)

## test: Run tests
test:
	go test -v ./...

## clean: Remove binary and temporary files
clean:
	rm -rf bin/
	rm -rf tmp/

## docker-up: Start docker-compose services (Postgres, Redis)
docker-up:
	docker-compose -f $(DOCKER_COMPOSE) up -d

## docker-down: Stop docker-compose services
docker-down:
	docker-compose -f $(DOCKER_COMPOSE) down

## lint: Run golangci-lint
lint:
	golangci-lint run

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%%-20s\033[0m %s\n", $$1, $$2}'
