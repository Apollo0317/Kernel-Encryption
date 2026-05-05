CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CPPFLAGS += -I../include -I/usr/include/libnl3
LDLIBS += -lnl-genl-3 -lnl-3

all: nl4enc

nl4enc: nl4enc.c ../include/nl4_netlink.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ nl4enc.c $(LDLIBS)

clean:
	rm -f nl4enc
