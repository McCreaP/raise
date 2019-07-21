CC=gcc
CFLAGS=-m32 -std=gnu11 -O0 -g -Wall
LDFLAGS=-static -T ld_script

all: raise

raise: raise.c load_registers.s
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@

clean:
	rm raise

.PHONY: all clean
