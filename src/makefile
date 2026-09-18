BINARIES = server
CC = gcc
CPP = g++
FLAGS = -pedantic -Wall -Wextra -Werror -fstack-protector-strong -O2 -g
RELEASEFLAGS = -O2
DBGFLAGS = -fstack-protector-strong -g
OBJ = server.o err.o
ODIR = obj

.PHONY: all clean

all: $(BINARIES)

err.o: err.c err.h
	$(CC) $(FLAGS) -std=c11 -c $< -o $@

server.o: server.cpp
	$(CPP) $(FLAGS) -std=c++17 -c $< -o $@

server: $(OBJ)
	$(CPP) $^ -lstdc++fs -o $@

clean:
	rm -f $(BINARIES) *.o
