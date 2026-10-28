BINARY      := winpass.exe
SRC_DIR     := src
BUILD_DIR   := dist
INSTALL_DIR ?= D:/customtools/bin

LDFLAGS := -s -w
GOENV   := GOOS=windows GOARCH=amd64

.PHONY: all build install clean

all: build

build:
	mkdir -p $(BUILD_DIR)
	cd $(SRC_DIR) && $(GOENV) go build -ldflags="$(LDFLAGS)" -o ../$(BUILD_DIR)/$(BINARY) .

install: build
	cp $(BUILD_DIR)/$(BINARY) $(INSTALL_DIR)/$(BINARY)

clean:
	rm -rf $(BUILD_DIR)
