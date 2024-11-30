# Default target: build all modules
all:
	$(MAKE) -C test/c

# Clean all modules
clean:
	$(MAKE) -C test/c clean
