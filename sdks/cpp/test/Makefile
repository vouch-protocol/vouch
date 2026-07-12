# Build and run the C++ ergonomic-layer tests against the prebuilt core library.
CXX     ?= g++
CXXFLAGS ?= -O2 -Wall -Wextra -std=c++17 -I../include
LDFLAGS ?= -L../lib -lvouch_core_uniffi

test_agent: test_agent.cpp ../include/vouch.hpp
	$(CXX) $(CXXFLAGS) test_agent.cpp -o test_agent $(LDFLAGS)

test_robotics: test_robotics.cpp ../include/vouch.hpp
	$(CXX) $(CXXFLAGS) test_robotics.cpp -o test_robotics $(LDFLAGS)

run: test_agent test_robotics
	LD_LIBRARY_PATH=../lib ./test_agent
	LD_LIBRARY_PATH=../lib ./test_robotics

clean:
	rm -f test_agent test_robotics

.PHONY: run clean
