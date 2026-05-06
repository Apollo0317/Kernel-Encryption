CC ?= cc
CFLAGS ?= -Wall -Wextra -O2
CPPFLAGS += -I../include -I/usr/include/libnl3
LDLIBS += -lnl-genl-3 -lnl-3 -lcrypto
SRCS := nl4enc.c nl4_common.c nl4_config.c nl4_genl.c nl4_kdf.c nl4_module.c nl4_route.c

all: nl4enc

nl4enc: $(SRCS) *.h ../include/nl4_netlink.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f nl4enc
