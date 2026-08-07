# Build and run the Vouch C bindings examples against the prebuilt core library.
#
# Every example links ../lib/libvouch_core_uniffi.so. That library is built
# separately from core/, so it can silently go stale relative to the Rust
# sources -- an example then "passes" while exercising the old core. The
# examples therefore depend on the library, and `make check-lib` warns when it
# is older than core/.
CC       ?= cc
CXX      ?= c++
CFLAGS   ?= -O2 -Wall -Wextra -std=c11 -I../include
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17 -I../include
LDFLAGS  ?= -L../lib -lvouch_core_uniffi
CORE_LIB ?= ../lib/libvouch_core_uniffi.so
CORE_SRC ?= ../../../core

$(CORE_LIB):
	@echo "error: $(CORE_LIB) is missing. Build it first:" >&2
	@echo "  cargo build --release --manifest-path ../../../core/uniffi/Cargo.toml" >&2
	@echo "  cp ../../../core/uniffi/target/release/libvouch_core_uniffi.so ../lib/" >&2
	@false

# Warn (do not fail) when the prebuilt library predates the Rust sources.
check-lib: $(CORE_LIB)
	@if [ -n "$$(find $(CORE_SRC) -name '*.rs' -newer $(CORE_LIB) -print -quit 2>/dev/null)" ]; then \
		echo "warning: $(CORE_LIB) is older than sources in $(CORE_SRC)." >&2; \
		echo "         Examples may exercise a stale core. Rebuild before trusting a pass." >&2; \
	fi

example: example.c $(CORE_LIB)
	$(CC) $(CFLAGS) example.c -o example $(LDFLAGS)

run: check-lib example
	LD_LIBRARY_PATH=../lib ./example

robotics_verify_example: robotics_verify_example.cpp $(CORE_LIB)
	$(CXX) $(CXXFLAGS) robotics_verify_example.cpp -o robotics_verify_example $(LDFLAGS)

run-robotics: check-lib robotics_verify_example
	LD_LIBRARY_PATH=../lib ./robotics_verify_example

robotics_example: robotics_example.c $(CORE_LIB)
	$(CC) $(CFLAGS) robotics_example.c -o robotics_example $(LDFLAGS)

run-robotics-c: check-lib robotics_example
	LD_LIBRARY_PATH=../lib ./robotics_example

clean:
	rm -f example robotics_verify_example robotics_example

.PHONY: check-lib run run-robotics run-robotics-c clean
