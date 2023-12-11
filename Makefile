.DEFAULT_GOAL := build

brew:
	brew install golangci-lint
	brew install staticcheck
	brew install gofumpt
	brew install protobuf

install:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

clean:
	rm -rf dist/
	rm -rf tmp/
	rm -f coverage.out
	rm -f result.json


init-dependency:
	go get -u github.com/antonfisher/nested-logrus-formatter
	go get -u golang.org/x/crypto
	# go get -u github.com/gin-gonic/gin
	# go get -u gorm.io/gorm
	# go get -u gorm.io/driver/postgres
	go get -u github.com/sirupsen/
	go get -u github.com/joho/godotenv
	go get -u github.com/go-playground/validator/v10@v10.15.1
	go get -u github.com/stretchr/testify@v1.8.4
	go get -u github.com/google/uuid@v1.3.1
	go get -u github.com/davecgh/go-spew/spew@v1.1.1
	go get -u github.com/xeipuuv/gojsonschema@v1.2.0
	go get -u google.golang.org/grpc@v1.59.0
	go get -u get github.com/dgraph-io/badger/v4
	go get -u github.com/jinzhu/copier@v0.4.0


mod:
	go mod download
	go mod tidy

protoc:
	protoc internal/api/pdp/v1/*.proto --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --proto_path=.

check:
	staticcheck  ./...

lint:
	go vet ./...
	gofmt -s -w **/**.go
	gofumpt -l -w .
	golangci-lint run --disable-all --enable staticcheck


lint-fix:
	gofmt -s -w **/**.go
	go vet ./...
	gofumpt -l -w .
	golangci-lint run ./... --fix

test:
	go test ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out
	rm coverage.out

converage-%:
	go test -coverprofile=coverage.out ./...

converage-json:
	go test -json -coverprofile=coverage.out ./... > result.json

build-release:
	mkdir -p dist
	go build -o dist/pdpagent ./cmd/pdpagent

build-docker:
	docker stop autenticami || true && docker rm autenticami || true
	docker build -t autenticami .

run-release:
	go run ./cmd/pdpagent

run-docker:
	docker run --name autenticami autenticami

build:  clean mod build-release

run:  clean mod lint-fix run-release

docker:  clean mod lint-fix run-docker

# disallow any parallelism (-j) for Make. This is necessary since some
# commands during the build process create temporary files that collide
# under parallel conditions.
.NOTPARALLEL:

.PHONY: clean mod lint lint-fix release alll
