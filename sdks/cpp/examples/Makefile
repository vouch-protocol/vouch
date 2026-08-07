# Build and run the Vouch C bindings example against the prebuilt core library.
CC       ?= cc
CXX      ?= c++
CFLAGS   ?= -O2 -Wall -Wextra -std=c11 -I../include
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17 -I../include
LDFLAGS  ?= -L../lib -lvouch_core_uniffi

example: example.c
	$(CC) $(CFLAGS) example.c -o example $(LDFLAGS)

run: example
	LD_LIBRARY_PATH=../lib ./example

robotics_verify_example: robotics_verify_example.cpp
	$(CXX) $(CXXFLAGS) robotics_verify_example.cpp -o robotics_verify_example $(LDFLAGS)

run-robotics: robotics_verify_example
	LD_LIBRARY_PATH=../lib ./robotics_verify_example

clean:
	rm -f example robotics_verify_example

.PHONY: run run-robotics clean
