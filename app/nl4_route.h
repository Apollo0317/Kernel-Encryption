#ifndef NL4_ROUTE_H
#define NL4_ROUTE_H

#include <arpa/inet.h>

int nl4_infer_src_ip(const struct in_addr *remote_addr,
		     struct in_addr *src_addr);

#endif
