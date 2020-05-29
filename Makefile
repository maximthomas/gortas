GOBlazewall_RELEASE_TAGS := $(shell go list -f ':{{join (context.ReleaseTags) ":"}}:' runtime)

# Only use the `-race` flag on newer versions of Go (version 1.3 and newer)
ifeq (,$(findstring :go1.3:,$(GO_RELEASE_TAGS)))
	RACE_FLAG :=
else
	RACE_FLAG := -race -cpu 1,2,4
endif

default: build quicktest

install:
	go get -t -v ./...

build:
	go build -v ./...

test:
	go test -v $(RACE_FLAG) -cover ./...

quicktest:
	go test ./...

vet:
	go vet ./...