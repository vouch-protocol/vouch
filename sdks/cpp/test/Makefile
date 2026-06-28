# Build and run the C++ ergonomic-layer tests against the prebuilt core library.
CXX     ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17 -I../include
LDFLAGS ?= -L../lib -lvouch_core_uniffi

test_agent: test_agent.cpp ../include/vouch.hpp
	$(CXX) $(CXXFLAGS) test_agent.cpp -o test_agent $(LDFLAGS)

run: test_agent
	LD_LIBRARY_PATH=../lib ./test_agent

clean:
	rm -f test_agent

.PHONY: run clean
