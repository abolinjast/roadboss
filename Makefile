.PHONY: generate build
generate:
	go generate ./cmd/roadboss
build:
	go build -o roadboss ./cmd/roadboss
