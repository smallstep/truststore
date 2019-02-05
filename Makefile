all:
	go build -o bin/truststore cmd/truststore/main.go

bootstrap:
	dep ensure

clean:
	rm -rf bin vendor

.PHONY: all bootstrap clean
