CXXFLAGS = -pedantic -Wall -Wextra -Werror -O2 -std=c++17
DBGFLAGS = -fstack-protector-strong -g
OBJ = $(BUILDDIR)/main.o $(BUILDDIR)/server.o $(BUILDDIR)/parameters.o $(BUILDDIR)/socket.o $(BUILDDIR)/parser.o
SRCDIR = src
BUILDDIR = build

.PHONY: all clean test

all: $(BUILDDIR)/server
	cp $< serwer

$(BUILDDIR)/parameters.o: $(SRCDIR)/parameters.cpp $(SRCDIR)/parameters.hpp $(SRCDIR)/exceptions.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/socket.o: $(SRCDIR)/socket.cpp $(SRCDIR)/socket.hpp $(SRCDIR)/exceptions.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/parser.o: $(SRCDIR)/parser.cpp $(SRCDIR)/parser.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/server.o: $(SRCDIR)/server.cpp $(SRCDIR)/server.hpp $(SRCDIR)/parameters.hpp $(SRCDIR)/parser.hpp $(SRCDIR)/socket.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# TODO dependencies
$(BUILDDIR)/main.o: $(SRCDIR)/main.cpp $(SRCDIR)/parameters.hpp $(SRCDIR)/exceptions.hpp $(SRCDIR)/server.hpp $(SRCDIR)/socket.hpp
	mkdir -p $(BUILDDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILDDIR)/server: $(OBJ)
	$(CXX) $^ -lstdc++fs -o $@

clean:
	rm -f serwer
	rm -rf $(BUILDDIR)
