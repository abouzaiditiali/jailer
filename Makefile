CC := gcc
CFLAGS := -std=gnu11 -Wall -Wextra -Wpedantic -O2 -Iinclude
SOURCES := src/main.c src/child.c src/cgroup.c src/rootfs.c src/userns.c src/security.c src/util.c
OBJECTS := $(SOURCES:.c=.o)
TARGET := jailer

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)
