CFLGAGS += -std=c99
LDFLAGS += -lpam

main: main.c
	$(CC) $(CFLAGS) $(LDFLAGS) -g -O0 -o main main.c

all: main

clean:
	rm -f main
