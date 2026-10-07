.PHONY: build

SOURCES = go.mod go.sum *.go

build: $(SOURCES)
	CGO_ENABLED=0 go build

clean:
	go clean

distclean:
	go clean -cache