# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Wextra -O2

# Libraries for linking
LIBS = -lssl -lcrypto -pthread

# Source files
SRCS = final.c

# Output executable
TARGET = final

# Default rule to build the program
all: $(TARGET)

# Rule to build the target executable
$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

# Clean rule to remove the compiled executable and object files
clean:
	rm -f $(TARGET)

# Rule for rebuilding the program
rebuild: clean all
