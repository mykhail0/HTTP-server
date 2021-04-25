BINARIES = serwer
CC = gcc
CPP = g++
FLAGS = -Wall -Wextra -O2 -g
OBJ = serwer.o err.o
ODIR = obj

.PHONY: all clean

all: $(BINARIES)

err.o: err.c err.h
	$(CC) $(FLAGS) -std=c11 -c $< -o $@

serwer.o: serwer.cpp
	$(CPP) $(FLAGS) -std=c++17 -c $< -o $@

serwer: $(OBJ)
	$(CPP) $^ -o $@

clean:
	rm -f $(BINARIES) *.o
