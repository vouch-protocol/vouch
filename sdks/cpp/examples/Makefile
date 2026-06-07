# Build and run the Vouch C bindings example against the prebuilt core library.
CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -I../include
LDFLAGS ?= -L../lib -lvouch_core_uniffi

example: example.c
	$(CC) $(CFLAGS) example.c -o example $(LDFLAGS)

run: example
	LD_LIBRARY_PATH=../lib ./example

clean:
	rm -f example

.PHONY: run clean
