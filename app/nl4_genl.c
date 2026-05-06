#include "nl4_genl.h"

#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <string.h>

int nl4_genl_open(struct nl4_ctx *ctx)
{
	int err;

	memset(ctx, 0, sizeof(*ctx));
	ctx->family_id = -1;
	ctx->sock = nl_socket_alloc();
	if (!ctx->sock)
		return -NLE_NOMEM;

	err = genl_connect(ctx->sock);
	if (err < 0)
		return err;

	ctx->family_id = genl_ctrl_resolve(ctx->sock, NL4_GENL_NAME);
	if (ctx->family_id < 0)
		return ctx->family_id;

	return 0;
}

void nl4_genl_close(struct nl4_ctx *ctx)
{
	if (ctx->sock)
		nl_socket_free(ctx->sock);
	ctx->sock = NULL;
}

static int send_rule_cmd(struct nl4_ctx *ctx, int cmd, uint32_t remote_ip,
			 uint8_t service_side, uint16_t service_port,
			 const uint8_t key[NL4_SHARED_KEY_LEN])
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg)
		return -NLE_NOMEM;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ctx->family_id, 0, 0,
			 cmd, NL4_GENL_VERSION)) {
		nlmsg_free(msg);
		return -NLE_NOMEM;
	}

	NLA_PUT_U32(msg, NL4_ATTR_REMOTE_IPV4, remote_ip);
	NLA_PUT_U8(msg, NL4_ATTR_SERVICE_SIDE, service_side);
	NLA_PUT_U16(msg, NL4_ATTR_SERVICE_PORT, service_port);
	if (key)
		NLA_PUT(msg, NL4_ATTR_SHARED_KEY, NL4_SHARED_KEY_LEN, key);

	err = nl_send_auto(ctx->sock, msg);
	if (err >= 0)
		err = nl_wait_for_ack(ctx->sock);
	nlmsg_free(msg);
	return err < 0 ? err : 0;

nla_put_failure:
	nlmsg_free(msg);
	return -NLE_MSGSIZE;
}

int nl4_genl_add_rule(struct nl4_ctx *ctx, const struct nl4_rule_cfg *rule)
{
	return send_rule_cmd(ctx, NL4_CMD_ADD_RULE, rule->remote_addr.s_addr,
			     rule->service_side, rule->service_port,
			     rule->shared_key);
}

int nl4_genl_flush_rules(struct nl4_ctx *ctx)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg)
		return -NLE_NOMEM;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ctx->family_id, 0, 0,
			 NL4_CMD_FLUSH_RULES, NL4_GENL_VERSION)) {
		nlmsg_free(msg);
		return -NLE_NOMEM;
	}

	err = nl_send_auto(ctx->sock, msg);
	if (err >= 0)
		err = nl_wait_for_ack(ctx->sock);
	nlmsg_free(msg);
	return err < 0 ? err : 0;
}
