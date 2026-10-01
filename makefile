CXXFLAGS = -pedantic -Wall -Wextra -Werror -O2
DBGFLAGS = -fstack-protector-strong -g
OBJ = $(BUILDDIR)/server.o $(BUILDDIR)/parameters.o
SRCDIR = src
BUILDDIR = build

.PHONY: all clean test

all: $(BUILDDIR)/server
	cp $< serwer

$(BUILDDIR)/parameters.o: $(SRCDIR)/parameters.cpp $(SRCDIR)/parameters.hpp $(SRCDIR)/exceptions.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -std=c++17 -c $< -o $@

$(BUILDDIR)/server.o: $(SRCDIR)/server.cpp $(SRCDIR)/exceptions.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -std=c++17 -c $< -o $@

$(BUILDDIR)/server: $(OBJ)
	$(CXX) $^ -lstdc++fs -o $@

clean:
	rm -f serwer
	rm -rf $(BUILDDIR)
