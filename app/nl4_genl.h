#ifndef NL4_GENL_H
#define NL4_GENL_H

#include "nl4_common.h"

#include <netlink/socket.h>

struct nl4_ctx {
	struct nl_sock *sock;
	int family_id;
};

int nl4_genl_open(struct nl4_ctx *ctx);
void nl4_genl_close(struct nl4_ctx *ctx);
int nl4_genl_add_rule(struct nl4_ctx *ctx, const struct nl4_rule_cfg *rule);
int nl4_genl_flush_rules(struct nl4_ctx *ctx);

#endif
