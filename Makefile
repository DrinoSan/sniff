# Makefile for compiling main.cpp with pcap library

# Compiler
CC = gcc

# Source files
SRC = main.c

# Output executable
TARGET = main

# Compiler flags
CFLAGS = -Wall

# Libraries to link
LIBS = -lpcap

# Default target to build the project
all: $(TARGET)

# Rule to build the target
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

# Clean up build files
clean:
	rm -f $(TARGET)
