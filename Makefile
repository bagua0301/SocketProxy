BIN := bin

ifeq ($(OS),Windows_NT)
EXE    := .exe
RM_BIN := cmd /c "if exist $(BIN) rmdir /s /q $(BIN)"
else
EXE    :=
RM_BIN := rm -rf $(BIN)
endif

CLIENT := $(BIN)/sp-client$(EXE)
SERVER := $(BIN)/sp-server$(EXE)

.PHONY: all build client server clean test vet

all: build

build: client server

client:
	go build -o $(CLIENT) ./cmd/sp-client

server:
	go build -o $(SERVER) ./cmd/sp-server

clean:
	$(RM_BIN)

test:
	go test ./...

vet:
	go vet ./...
