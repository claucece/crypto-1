default: lint test

ci: lint test

lint:
	golint

test:
	go test -cover -v ./...

test-v:
	go test -check.vv -cover ./...

deps-u:
	go get -u github.com/twstrike/ed448

deps:
	go get github.com/golang/lint/golint
	go get github.com/twstrike/ed448
	go get -t -v ./...
