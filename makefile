CFLAGS += -Wall
LDLIBS += -lpcap

all: tcp-block

tcp-block: main.c
	gcc $(CFLAGS) -o tcp-block main.c $(LDLIBS)

clean:
	rm -f tcp-block *.o
