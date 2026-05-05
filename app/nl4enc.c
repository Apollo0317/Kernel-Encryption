#include <arpa/inet.h>
#include <errno.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nl4_netlink.h>

struct nl4_ctx {
	struct nl_sock *sock;
	int family_id;
};

static void usage(FILE *out)
{
	fprintf(out,
		"Usage:\n"
		"  nl4enc rule add <remote-ip> --key <64hex> --remote-service <port>\n"
		"  nl4enc rule add <remote-ip> --key <64hex> --local-service <port>\n"
		"  nl4enc rule add <remote-ip> --key <64hex> --all-ports\n"
		"  nl4enc rule delete <remote-ip> --remote-service <port>\n"
		"  nl4enc rule delete <remote-ip> --local-service <port>\n"
		"  nl4enc rule delete <remote-ip> --all-ports\n"
		"  nl4enc rule list\n"
		"  nl4enc rule flush\n");
}

static void print_nl_error(const char *op, int err)
{
	if (err == -NLE_OBJ_NOTFOUND || err == -ENOENT)
		fprintf(stderr, "%s: module not loaded\n", op);
	else if (err == -NLE_PERM || err == -EPERM || err == -EACCES)
		fprintf(stderr, "%s: permission denied, try sudo\n", op);
	else
		fprintf(stderr, "%s: %s\n", op, nl_geterror(err));
}

static int parse_port(const char *arg, uint16_t *port)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(arg, &end, 10);
	if (errno || *arg == '\0' || *end != '\0' || value < 1 || value > 65535)
		return -1;
	*port = (uint16_t)value;
	return 0;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int parse_key(const char *hex, uint8_t key[NL4_SHARED_KEY_LEN])
{
	size_t i;

	if (strlen(hex) != NL4_SHARED_KEY_LEN * 2)
		return -1;

	for (i = 0; i < NL4_SHARED_KEY_LEN; i++) {
		int hi = hexval(hex[i * 2]);
		int lo = hexval(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -1;
		key[i] = (uint8_t)((hi << 4) | lo);
	}

	return 0;
}

static const char *service_side_name(uint8_t side)
{
	switch (side) {
	case NL4_SERVICE_REMOTE:
		return "remote-service";
	case NL4_SERVICE_LOCAL:
		return "local-service";
	case NL4_SERVICE_ALL_PORTS:
		return "all-ports";
	default:
		return "unknown";
	}
}

static int parse_service_arg(int argc, char **argv, uint8_t *side,
			     uint16_t *port)
{
	int seen = 0;
	int i;

	*side = 0;
	*port = 0;

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--remote-service") == 0 && i + 1 < argc) {
			if (seen++ || parse_port(argv[++i], port) < 0)
				return -1;
			*side = NL4_SERVICE_REMOTE;
		} else if (strcmp(argv[i], "--local-service") == 0 && i + 1 < argc) {
			if (seen++ || parse_port(argv[++i], port) < 0)
				return -1;
			*side = NL4_SERVICE_LOCAL;
		} else if (strcmp(argv[i], "--all-ports") == 0) {
			if (seen++)
				return -1;
			*side = NL4_SERVICE_ALL_PORTS;
			*port = 0;
		} else {
			return -1;
		}
	}

	return seen == 1 ? 0 : -1;
}

static int nl4_open(struct nl4_ctx *ctx)
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

static void nl4_close(struct nl4_ctx *ctx)
{
	if (ctx->sock)
		nl_socket_free(ctx->sock);
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

static int cmd_add(struct nl4_ctx *ctx, int argc, char **argv)
{
	struct in_addr remote_addr;
	uint8_t key[NL4_SHARED_KEY_LEN];
	const char *key_hex = NULL;
	uint8_t side;
	uint16_t port;
	int service_start = 1;
	int err;

	if (argc < 4 || inet_pton(AF_INET, argv[0], &remote_addr) != 1)
		return -EINVAL;

	if (strcmp(argv[1], "--key") == 0 && argc >= 3) {
		key_hex = argv[2];
		service_start = 3;
	} else {
		return -EINVAL;
	}

	if (parse_key(key_hex, key) < 0 ||
	    parse_service_arg(argc - service_start, argv + service_start,
			      &side, &port) < 0)
		return -EINVAL;

	err = send_rule_cmd(ctx, NL4_CMD_ADD_RULE, remote_addr.s_addr, side,
			    port, key);
	return err;
}

static int cmd_delete(struct nl4_ctx *ctx, int argc, char **argv)
{
	struct in_addr remote_addr;
	uint8_t side;
	uint16_t port;

	if (argc < 2 || inet_pton(AF_INET, argv[0], &remote_addr) != 1)
		return -EINVAL;
	if (parse_service_arg(argc - 1, argv + 1, &side, &port) < 0)
		return -EINVAL;

	return send_rule_cmd(ctx, NL4_CMD_DELETE_RULE, remote_addr.s_addr, side,
			     port, NULL);
}

static int cmd_flush(struct nl4_ctx *ctx)
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

static int list_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[NL4_ATTR_MAX + 1];
	struct genlmsghdr *genlh = nlmsg_data(nlmsg_hdr(msg));
	struct in_addr remote_addr = { 0 };
	uint8_t side = 0;
	uint16_t port = 0;

	(void)arg;

	if (nla_parse(attrs, NL4_ATTR_MAX, genlmsg_attrdata(genlh, 0),
		      genlmsg_attrlen(genlh, 0), NULL) < 0)
		return NL_SKIP;

	if (attrs[NL4_ATTR_REMOTE_IPV4])
		remote_addr.s_addr = nla_get_u32(attrs[NL4_ATTR_REMOTE_IPV4]);
	if (attrs[NL4_ATTR_SERVICE_SIDE])
		side = nla_get_u8(attrs[NL4_ATTR_SERVICE_SIDE]);
	if (attrs[NL4_ATTR_SERVICE_PORT])
		port = nla_get_u16(attrs[NL4_ATTR_SERVICE_PORT]);

	if (side == NL4_SERVICE_ALL_PORTS)
		printf("%s all-ports\n", inet_ntoa(remote_addr));
	else
		printf("%s %s=%u\n", inet_ntoa(remote_addr),
		       service_side_name(side), port);

	return NL_OK;
}

static int cmd_list(struct nl4_ctx *ctx)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg)
		return -NLE_NOMEM;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ctx->family_id, 0,
			 NLM_F_DUMP, NL4_CMD_LIST_RULES, NL4_GENL_VERSION)) {
		nlmsg_free(msg);
		return -NLE_NOMEM;
	}

	nl_socket_modify_cb(ctx->sock, NL_CB_VALID, NL_CB_CUSTOM, list_cb,
			    NULL);
	err = nl_send_auto(ctx->sock, msg);
	if (err >= 0)
		err = nl_recvmsgs_default(ctx->sock);
	nlmsg_free(msg);
	return err < 0 ? err : 0;
}

int main(int argc, char **argv)
{
	struct nl4_ctx ctx;
	int err;

	if (argc < 3 || strcmp(argv[1], "rule") != 0) {
		usage(stderr);
		return 2;
	}

	err = nl4_open(&ctx);
	if (err < 0) {
		print_nl_error("nl4enc", err);
		nl4_close(&ctx);
		return 1;
	}

	if (strcmp(argv[2], "add") == 0)
		err = cmd_add(&ctx, argc - 3, argv + 3);
	else if (strcmp(argv[2], "delete") == 0)
		err = cmd_delete(&ctx, argc - 3, argv + 3);
	else if (strcmp(argv[2], "list") == 0 && argc == 3)
		err = cmd_list(&ctx);
	else if (strcmp(argv[2], "flush") == 0 && argc == 3)
		err = cmd_flush(&ctx);
	else
		err = -EINVAL;

	if (err < 0) {
		if (err == -EINVAL)
			usage(stderr);
		else
			print_nl_error("nl4enc", err);
		nl4_close(&ctx);
		return 1;
	}

	nl4_close(&ctx);
	return 0;
}
