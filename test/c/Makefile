# Compiler and flags
CC = i686-linux-gnu-gcc
CFLAGS = -m32 -O0

# Directories
SRC_DIR = .
BIN_DIR = ../bin

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)
BINS = $(patsubst $(SRC_DIR)/%.c, $(BIN_DIR)/%, $(SRCS))

# Default target: build all binaries
all: $(BINS)

# Rule to build each binary
$(BIN_DIR)/%: $(SRC_DIR)/%.c
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Clean target to remove binaries
clean:
	rm -f $(BIN_DIR)/*

# Phony targets
.PHONY: all clean
