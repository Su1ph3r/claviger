# Claviger build + release
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/Su1ph3r/claviger/cmd.version=$(VERSION)

.PHONY: build test e2e release snapshot clean

build:
	go build -ldflags "$(LDFLAGS)" -o claviger .

test:
	go test ./... -race

# e2e runs the acceptance harness: it drives the real binary against a
# self-signed HTTPS target with real tooling (curl, ffuf, nuclei, sqlmap,
# headless Chrome, corpus replay) and exits non-zero if any assertion fails.
e2e: build
	bash e2e/run.sh

# release builds and publishes tagged binaries; requires goreleaser and a git tag.
release:
	goreleaser release --clean

# snapshot builds the release artifacts locally without publishing or a tag.
snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f claviger
	rm -rf dist
