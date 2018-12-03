.PHONY: build clean deploy

build:
	env GOOS=linux go build -ldflags="-s -w" -o bin/func1 func1/main.go
	env GOOS=linux go build -ldflags="-s -w" -o bin/auth auth/main.go

clean:
	rm -rf ./bin

deploy: clean build
	sls deploy --verbose
