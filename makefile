CC = gcc
CPP = g++
FLAGS = -pedantic -Wall -Wextra -Werror
RELEASEFLAGS = -O2
DBGFLAGS = -fstack-protector-strong -g
OBJ = $(BUILDDIR)/server.o $(BUILDDIR)/err.o
SRCDIR = src
BUILDDIR = build

.PHONY: all clean

all: $(BUILDDIR)/server
	cp $< serwer

$(BUILDDIR)/err.o: $(SRCDIR)/err.c $(SRCDIR)/err.h
	mkdir -p $(BUILDDIR)
	$(CC) $(FLAGS) -std=c11 -c $< -o $@

$(BUILDDIR)/server.o: $(SRCDIR)/server.cpp
	mkdir -p $(BUILDDIR)
	$(CPP) $(FLAGS) -std=c++17 -c $< -o $@

$(BUILDDIR)/server: $(OBJ)
	$(CPP) $^ -lstdc++fs -o $@

clean:
	rm -f serwer
	rm -rf $(BUILDDIR)
