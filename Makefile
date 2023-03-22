CFLGAGS += -std=c99
LDFLAGS += $(shell pkg-config --libs pam)

main: main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -g -O0 -o main main.c

all: main

clean:
	rm -f main
