CC = gcc
CFLAGS = -Wall -Wextra -O2

all: injector dummy_hello_world

injector: injector.c elf_debug.c elf_debug.h
	$(CC) $(CFLAGS) -o injector injector.c elf_debug.c

dummy_hello_world: dummy_hello_world.c
	$(CC) $(CFLAGS) -o dummy_hello_world dummy_hello_world.c

clean:
	rm -f injector dummy_hello_world new_elf_file

.PHONY: all clean
