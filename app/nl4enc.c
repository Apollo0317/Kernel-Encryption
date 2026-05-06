/**
 * @Author: Apollo
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <nl4_netlink.h>

#define NL4_CONFIG_DIR "/etc/nl4enc"
#define NL4_RULES_PATH NL4_CONFIG_DIR "/rules.json"
#define NL4_RULES_TMP_PATH NL4_CONFIG_DIR "/rules.json.tmp"
#define NL4_MODULE_NAME "nl4_bypass"
#define NL4_DEFAULT_KDF_ITERATIONS 200000
#define NL4_KDF_VERSION "pbkdf2-hmac-sha256-v1"
#define NL4_RAW_KEY_VERSION "raw-key-v1"
#define NL4_SALT_PREFIX "nl4enc-v1"
#define NL4_MAX_SALT_LEN 64
#define NL4_ERR_QUIET (-100000)

struct nl4_ctx {
	struct nl_sock *sock;
	int family_id;
};

struct nl4_rule_cfg {
	struct in_addr remote_addr;
	struct in_addr src_addr;
	uint8_t service_side;
	uint16_t service_port;
	uint8_t shared_key[NL4_SHARED_KEY_LEN];
	char key_fingerprint[SHA256_DIGEST_LENGTH + 1];
	char kdf_version[32];
	unsigned int kdf_iterations;
	uint8_t salt[NL4_MAX_SALT_LEN];
	size_t salt_len;
};

struct nl4_rule_vec {
	struct nl4_rule_cfg *items;
	size_t len;
	size_t cap;
};

struct add_args {
	struct in_addr remote_addr;
	struct in_addr src_addr;
	bool has_src_ip;
	bool replace;
	bool use_psk;
	bool use_key;
	const char *psk;
	uint8_t key[NL4_SHARED_KEY_LEN];
	uint8_t service_side;
	uint16_t service_port;
};

static bool module_is_loaded(void);

static void usage(FILE *out)
{
	fprintf(out,
		"Usage:\n"
		"  nl4enc rule add <remote-ip> --psk <psk> --remote-service <port> [--src-ip <local-ip>] [--replace]\n"
		"  nl4enc rule add <remote-ip> --psk <psk> --local-service <port> [--src-ip <local-ip>] [--replace]\n"
		"  nl4enc rule add <remote-ip> --psk <psk> --all-ports [--src-ip <local-ip>] [--replace]\n"
		"  nl4enc rule add <remote-ip> --key <64hex> --remote-service <port> [--src-ip <local-ip>] [--replace]\n"
		"  nl4enc rule add <remote-ip> --key <64hex> --local-service <port> [--src-ip <local-ip>] [--replace]\n"
		"  nl4enc rule add <remote-ip> --key <64hex> --all-ports [--src-ip <local-ip>] [--replace]\n"
		"  nl4enc rule delete <remote-ip> --remote-service <port>\n"
		"  nl4enc rule delete <remote-ip> --local-service <port>\n"
		"  nl4enc rule delete <remote-ip> --all-ports\n"
		"  nl4enc rule list\n"
		"  nl4enc rule flush\n"
		"  nl4enc apply\n"
		"  nl4enc on [--apply]\n"
		"  nl4enc stop\n");
}

static void print_error(const char *op, int err)
{
	if (err == -NLE_OBJ_NOTFOUND || err == -ENOENT)
		fprintf(stderr, "%s: module not loaded\n", op);
	else if (err == -NLE_PERM || err == -EPERM || err == -EACCES)
		fprintf(stderr, "%s: permission denied, try sudo\n", op);
	else if (err == -EEXIST)
		fprintf(stderr, "%s: rule already exists; use --replace\n", op);
	else if (err == -ESRCH)
		fprintf(stderr, "%s: rule not found\n", op);
	else if (err < 0 && -err < 4096)
		fprintf(stderr, "%s: %s\n", op, strerror(-err));
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
		return -EINVAL;
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

static int parse_hex_exact(const char *hex, uint8_t *out, size_t out_len)
{
	size_t i;

	if (strlen(hex) != out_len * 2)
		return -EINVAL;

	for (i = 0; i < out_len; i++) {
		int hi = hexval(hex[i * 2]);
		int lo = hexval(hex[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)((hi << 4) | lo);
	}

	return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
	static const char table[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		hex[i * 2] = table[bytes[i] >> 4];
		hex[i * 2 + 1] = table[bytes[i] & 0xf];
	}
	hex[len * 2] = '\0';
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

static int parse_service_side_name(const char *name, uint8_t *side)
{
	if (strcmp(name, "remote-service") == 0)
		*side = NL4_SERVICE_REMOTE;
	else if (strcmp(name, "local-service") == 0)
		*side = NL4_SERVICE_LOCAL;
	else if (strcmp(name, "all-ports") == 0)
		*side = NL4_SERVICE_ALL_PORTS;
	else
		return -EINVAL;

	return 0;
}

static int parse_service_arg(int argc, char **argv, uint8_t *side,
			     uint16_t *port, int *used)
{
	if (strcmp(argv[0], "--remote-service") == 0 && argc >= 2) {
		if (parse_port(argv[1], port) < 0)
			return -EINVAL;
		*side = NL4_SERVICE_REMOTE;
		*used = 2;
		return 0;
	}
	if (strcmp(argv[0], "--local-service") == 0 && argc >= 2) {
		if (parse_port(argv[1], port) < 0)
			return -EINVAL;
		*side = NL4_SERVICE_LOCAL;
		*used = 2;
		return 0;
	}
	if (strcmp(argv[0], "--all-ports") == 0) {
		*side = NL4_SERVICE_ALL_PORTS;
		*port = 0;
		*used = 1;
		return 0;
	}

	return -EINVAL;
}

static void rule_vec_free(struct nl4_rule_vec *rules)
{
	free(rules->items);
	rules->items = NULL;
	rules->len = 0;
	rules->cap = 0;
}

static int rule_vec_push(struct nl4_rule_vec *rules,
			 const struct nl4_rule_cfg *rule)
{
	struct nl4_rule_cfg *new_items;
	size_t new_cap;

	if (rules->len == rules->cap) {
		new_cap = rules->cap ? rules->cap * 2 : 8;
		new_items = realloc(rules->items, new_cap * sizeof(*new_items));
		if (!new_items)
			return -ENOMEM;
		rules->items = new_items;
		rules->cap = new_cap;
	}

	rules->items[rules->len++] = *rule;
	return 0;
}

static ssize_t find_rule_index(const struct nl4_rule_vec *rules,
			       const struct in_addr *remote_addr,
			       uint8_t service_side, uint16_t service_port)
{
	size_t i;

	for (i = 0; i < rules->len; i++) {
		const struct nl4_rule_cfg *rule = &rules->items[i];

		if (rule->remote_addr.s_addr == remote_addr->s_addr &&
		    rule->service_side == service_side &&
		    rule->service_port == service_port)
			return (ssize_t)i;
	}

	return -1;
}

static char *read_text_file(const char *path, size_t *len_out)
{
	FILE *fp;
	char *buf;
	long len;

	fp = fopen(path, "rb");
	if (!fp) {
		if (errno == ENOENT) {
			*len_out = 0;
			return NULL;
		}
		return (char *)(intptr_t)-errno;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		int err = errno;

		fclose(fp);
		return (char *)(intptr_t)-err;
	}
	len = ftell(fp);
	if (len < 0) {
		int err = errno;

		fclose(fp);
		return (char *)(intptr_t)-err;
	}
	rewind(fp);

	buf = calloc((size_t)len + 1, 1);
	if (!buf) {
		fclose(fp);
		return (char *)(intptr_t)-ENOMEM;
	}
	if (len > 0 && fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		int err = ferror(fp) ? errno : EINVAL;

		free(buf);
		fclose(fp);
		return (char *)(intptr_t)-err;
	}
	fclose(fp);
	*len_out = (size_t)len;
	return buf;
}

static char *skip_ws(char *p, const char *end)
{
	while (p < end && isspace((unsigned char)*p))
		p++;
	return p;
}

static int json_get_string(char *obj, char *end, const char *key,
			   char *out, size_t out_len)
{
	char pattern[64];
	char *p;
	char *q;
	size_t len = 0;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(obj, pattern);
	if (!p || p >= end)
		return -EINVAL;
	p += strlen(pattern);
	p = skip_ws(p, end);
	if (p >= end || *p++ != ':')
		return -EINVAL;
	p = skip_ws(p, end);
	if (p >= end || *p++ != '"')
		return -EINVAL;
	q = p;
	while (q < end && *q != '"')
		q++;
	if (q >= end)
		return -EINVAL;
	len = (size_t)(q - p);
	if (len >= out_len)
		return -EINVAL;
	memcpy(out, p, len);
	out[len] = '\0';
	return 0;
}

static int json_get_uint(char *obj, char *end, const char *key,
			 unsigned int *value)
{
	char pattern[64];
	char *p;
	char *num_end;
	unsigned long parsed;

	snprintf(pattern, sizeof(pattern), "\"%s\"", key);
	p = strstr(obj, pattern);
	if (!p || p >= end)
		return -EINVAL;
	p += strlen(pattern);
	p = skip_ws(p, end);
	if (p >= end || *p++ != ':')
		return -EINVAL;
	p = skip_ws(p, end);

	errno = 0;
	parsed = strtoul(p, &num_end, 10);
	if (errno || num_end == p || num_end > end || parsed > UINT32_MAX)
		return -EINVAL;
	*value = (unsigned int)parsed;
	return 0;
}

static int parse_rule_object(char *obj, char *end, struct nl4_rule_cfg *rule)
{
	char remote_ip[INET_ADDRSTRLEN];
	char src_ip[INET_ADDRSTRLEN];
	char service_side[32];
	char shared_key_hex[NL4_SHARED_KEY_LEN * 2 + 1];
	char salt_hex[NL4_MAX_SALT_LEN * 2 + 1];
	unsigned int port;
	unsigned int iterations;
	size_t salt_hex_len;

	memset(rule, 0, sizeof(*rule));

	if (json_get_string(obj, end, "remote_ip", remote_ip, sizeof(remote_ip)) < 0 ||
	    json_get_string(obj, end, "src_ip", src_ip, sizeof(src_ip)) < 0 ||
	    json_get_string(obj, end, "service_side", service_side,
			    sizeof(service_side)) < 0 ||
	    json_get_uint(obj, end, "service_port", &port) < 0 ||
	    json_get_string(obj, end, "shared_key", shared_key_hex,
			    sizeof(shared_key_hex)) < 0 ||
	    json_get_string(obj, end, "key_fingerprint", rule->key_fingerprint,
			    sizeof(rule->key_fingerprint)) < 0 ||
	    json_get_string(obj, end, "kdf_version", rule->kdf_version,
			    sizeof(rule->kdf_version)) < 0 ||
	    json_get_uint(obj, end, "kdf_iterations", &iterations) < 0 ||
	    json_get_string(obj, end, "salt", salt_hex, sizeof(salt_hex)) < 0)
		return -EINVAL;

	if (inet_pton(AF_INET, remote_ip, &rule->remote_addr) != 1 ||
	    inet_pton(AF_INET, src_ip, &rule->src_addr) != 1 ||
	    parse_service_side_name(service_side, &rule->service_side) < 0 ||
	    port > 65535 ||
	    parse_hex_exact(shared_key_hex, rule->shared_key,
			    sizeof(rule->shared_key)) < 0)
		return -EINVAL;

	if (rule->service_side == NL4_SERVICE_ALL_PORTS) {
		if (port != 0)
			return -EINVAL;
	} else if (port == 0) {
		return -EINVAL;
	}
	rule->service_port = (uint16_t)port;
	rule->kdf_iterations = iterations;

	salt_hex_len = strlen(salt_hex);
	if (salt_hex_len % 2 != 0 || salt_hex_len / 2 > sizeof(rule->salt))
		return -EINVAL;
	rule->salt_len = salt_hex_len / 2;
	if (rule->salt_len &&
	    parse_hex_exact(salt_hex, rule->salt, rule->salt_len) < 0)
		return -EINVAL;

	return 0;
}

static int load_rules(struct nl4_rule_vec *rules)
{
	size_t len = 0;
	char *buf;
	char *p;
	char *end;
	int err = 0;

	memset(rules, 0, sizeof(*rules));
	buf = read_text_file(NL4_RULES_PATH, &len);
	if (!buf)
		return 0;
	if ((intptr_t)buf < 0)
		return (int)(intptr_t)buf;

	p = buf;
	end = buf + len;
	while ((p = memchr(p, '{', (size_t)(end - p))) != NULL) {
		char *obj_end = memchr(p, '}', (size_t)(end - p));
		struct nl4_rule_cfg rule;

		if (!obj_end) {
			err = -EINVAL;
			break;
		}
		if (parse_rule_object(p, obj_end, &rule) < 0 ||
		    rule_vec_push(rules, &rule) < 0) {
			err = -EINVAL;
			break;
		}
		p = obj_end + 1;
	}

	free(buf);
	if (err < 0)
		rule_vec_free(rules);
	return err;
}

static int ensure_config_dir(void)
{
	struct stat st;

	if (mkdir(NL4_CONFIG_DIR, 0700) < 0 && errno != EEXIST)
		return -errno;
	if (stat(NL4_CONFIG_DIR, &st) < 0)
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;
	if (chmod(NL4_CONFIG_DIR, 0700) < 0)
		return -errno;
	if (geteuid() == 0 && chown(NL4_CONFIG_DIR, 0, 0) < 0)
		return -errno;

	return 0;
}

static int save_rules(const struct nl4_rule_vec *rules)
{
	FILE *fp;
	int fd;
	size_t i;
	int err;

	err = ensure_config_dir();
	if (err < 0)
		return err;

	fd = open(NL4_RULES_TMP_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -errno;
	if (fchmod(fd, 0600) < 0) {
		err = -errno;
		close(fd);
		return err;
	}
	if (geteuid() == 0 && fchown(fd, 0, 0) < 0) {
		err = -errno;
		close(fd);
		return err;
	}

	fp = fdopen(fd, "w");
	if (!fp) {
		err = -errno;
		close(fd);
		return err;
	}

	fprintf(fp, "[\n");
	for (i = 0; i < rules->len; i++) {
		const struct nl4_rule_cfg *rule = &rules->items[i];
		char remote_ip[INET_ADDRSTRLEN];
		char src_ip[INET_ADDRSTRLEN];
		char shared_key_hex[NL4_SHARED_KEY_LEN * 2 + 1];
		char salt_hex[NL4_MAX_SALT_LEN * 2 + 1];

		inet_ntop(AF_INET, &rule->remote_addr, remote_ip,
			  sizeof(remote_ip));
		inet_ntop(AF_INET, &rule->src_addr, src_ip, sizeof(src_ip));
		bytes_to_hex(rule->shared_key, sizeof(rule->shared_key),
			     shared_key_hex);
		bytes_to_hex(rule->salt, rule->salt_len, salt_hex);

		fprintf(fp,
			"  {\n"
			"    \"remote_ip\": \"%s\",\n"
			"    \"src_ip\": \"%s\",\n"
			"    \"service_side\": \"%s\",\n"
			"    \"service_port\": %u,\n"
			"    \"shared_key\": \"%s\",\n"
			"    \"key_fingerprint\": \"%s\",\n"
			"    \"kdf_version\": \"%s\",\n"
			"    \"kdf_iterations\": %u,\n"
			"    \"salt\": \"%s\"\n"
			"  }%s\n",
			remote_ip, src_ip, service_side_name(rule->service_side),
			rule->service_port, shared_key_hex, rule->key_fingerprint,
			rule->kdf_version, rule->kdf_iterations, salt_hex,
			i + 1 == rules->len ? "" : ",");
	}
	fprintf(fp, "]\n");

	if (fflush(fp) != 0) {
		err = -errno;
		fclose(fp);
		return err;
	}
	if (fsync(fd) < 0) {
		err = -errno;
		fclose(fp);
		return err;
	}
	if (fclose(fp) != 0)
		return -errno;
	if (rename(NL4_RULES_TMP_PATH, NL4_RULES_PATH) < 0)
		return -errno;
	if (chmod(NL4_RULES_PATH, 0600) < 0)
		return -errno;
	if (geteuid() == 0 && chown(NL4_RULES_PATH, 0, 0) < 0)
		return -errno;

	return 0;
}

static void make_fingerprint(const uint8_t key[NL4_SHARED_KEY_LEN],
			     char fingerprint[SHA256_DIGEST_LENGTH + 1])
{
	uint8_t digest[SHA256_DIGEST_LENGTH];

	SHA256(key, NL4_SHARED_KEY_LEN, digest);
	bytes_to_hex(digest, 8, fingerprint);
}

static void make_salt(const struct in_addr *src_addr,
		      const struct in_addr *remote_addr,
		      uint8_t salt[NL4_MAX_SALT_LEN], size_t *salt_len)
{
	const uint8_t *a = (const uint8_t *)&src_addr->s_addr;
	const uint8_t *b = (const uint8_t *)&remote_addr->s_addr;
	const uint8_t *first = a;
	const uint8_t *second = b;
	size_t prefix_len = strlen(NL4_SALT_PREFIX);

	if (memcmp(a, b, 4) > 0) {
		first = b;
		second = a;
	}

	memcpy(salt, NL4_SALT_PREFIX, prefix_len);
	memcpy(salt + prefix_len, first, 4);
	memcpy(salt + prefix_len + 4, second, 4);
	*salt_len = prefix_len + 8;
}

static int derive_psk_key(const char *psk, const uint8_t *salt, size_t salt_len,
			  uint8_t key[NL4_SHARED_KEY_LEN])
{
	if (!PKCS5_PBKDF2_HMAC(psk, (int)strlen(psk), salt, (int)salt_len,
			       NL4_DEFAULT_KDF_ITERATIONS, EVP_sha256(),
			       NL4_SHARED_KEY_LEN, key))
		return -EINVAL;

	return 0;
}

static int infer_src_ip(const struct in_addr *remote_addr,
			struct in_addr *src_addr)
{
	char remote_ip[INET_ADDRSTRLEN];
	char cmd[128];
	char line[512];
	FILE *fp;
	char *token;
	int ret = -EINVAL;

	if (!inet_ntop(AF_INET, remote_addr, remote_ip, sizeof(remote_ip)))
		return -EINVAL;

	snprintf(cmd, sizeof(cmd), "ip route get %s", remote_ip);
	fp = popen(cmd, "r");
	if (!fp)
		return -errno;

	if (!fgets(line, sizeof(line), fp)) {
		pclose(fp);
		return -EINVAL;
	}
	for (token = strtok(line, " \t\r\n"); token;
	     token = strtok(NULL, " \t\r\n")) {
		if (strcmp(token, "src") == 0) {
			char *src = strtok(NULL, " \t\r\n");

			if (src && inet_pton(AF_INET, src, src_addr) == 1)
				ret = 0;
			break;
		}
	}
	pclose(fp);
	return ret;
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

static int send_flush_cmd(struct nl4_ctx *ctx)
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

static int parse_add_args(int argc, char **argv, struct add_args *args)
{
	int service_count = 0;
	int i;

	memset(args, 0, sizeof(*args));
	if (argc < 2 || inet_pton(AF_INET, argv[0], &args->remote_addr) != 1)
		return -EINVAL;

	for (i = 1; i < argc; i++) {
		int used = 0;

		if (strcmp(argv[i], "--psk") == 0 && i + 1 < argc) {
			if (args->use_key || args->use_psk)
				return -EINVAL;
			args->use_psk = true;
			args->psk = argv[++i];
			if (args->psk[0] == '\0')
				return -EINVAL;
		} else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
			if (args->use_key || args->use_psk)
				return -EINVAL;
			if (parse_hex_exact(argv[++i], args->key,
					    sizeof(args->key)) < 0)
				return -EINVAL;
			args->use_key = true;
		} else if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
			if (args->has_src_ip ||
			    inet_pton(AF_INET, argv[++i], &args->src_addr) != 1)
				return -EINVAL;
			args->has_src_ip = true;
		} else if (strcmp(argv[i], "--replace") == 0) {
			if (args->replace)
				return -EINVAL;
			args->replace = true;
		} else if (parse_service_arg(argc - i, argv + i,
					     &args->service_side,
					     &args->service_port, &used) == 0) {
			if (service_count++)
				return -EINVAL;
			i += used - 1;
		} else {
			return -EINVAL;
		}
	}

	if ((!args->use_psk && !args->use_key) || service_count != 1)
		return -EINVAL;

	return 0;
}

static int parse_delete_args(int argc, char **argv, struct in_addr *remote_addr,
			     uint8_t *service_side, uint16_t *service_port)
{
	int used = 0;

	if (argc < 2 || inet_pton(AF_INET, argv[0], remote_addr) != 1)
		return -EINVAL;
	if (parse_service_arg(argc - 1, argv + 1, service_side, service_port,
			      &used) < 0 || used != argc - 1)
		return -EINVAL;

	return 0;
}

static int cmd_rule_add(int argc, char **argv)
{
	struct nl4_rule_vec rules;
	struct nl4_rule_cfg rule;
	struct add_args args;
	ssize_t idx;
	int err;

	err = parse_add_args(argc, argv, &args);
	if (err < 0)
		return err;

	if (!args.has_src_ip) {
		err = infer_src_ip(&args.remote_addr, &args.src_addr);
		if (err < 0) {
			fprintf(stderr,
				"nl4enc: unable to infer source IP; use --src-ip <local-ip>\n");
			return NL4_ERR_QUIET;
		}
	}

	memset(&rule, 0, sizeof(rule));
	rule.remote_addr = args.remote_addr;
	rule.src_addr = args.src_addr;
	rule.service_side = args.service_side;
	rule.service_port = args.service_port;

	if (args.use_psk) {
		make_salt(&rule.src_addr, &rule.remote_addr, rule.salt,
			  &rule.salt_len);
		err = derive_psk_key(args.psk, rule.salt, rule.salt_len,
				     rule.shared_key);
		if (err < 0)
			return err;
		snprintf(rule.kdf_version, sizeof(rule.kdf_version), "%s",
			 NL4_KDF_VERSION);
		rule.kdf_iterations = NL4_DEFAULT_KDF_ITERATIONS;
	} else {
		memcpy(rule.shared_key, args.key, sizeof(rule.shared_key));
		snprintf(rule.kdf_version, sizeof(rule.kdf_version), "%s",
			 NL4_RAW_KEY_VERSION);
		rule.kdf_iterations = 0;
	}
	make_fingerprint(rule.shared_key, rule.key_fingerprint);

	err = load_rules(&rules);
	if (err < 0)
		return err;

	idx = find_rule_index(&rules, &rule.remote_addr, rule.service_side,
			      rule.service_port);
	if (idx >= 0 && !args.replace) {
		rule_vec_free(&rules);
		return -EEXIST;
	}
	if (idx >= 0) {
		rules.items[idx] = rule;
	} else {
		err = rule_vec_push(&rules, &rule);
		if (err < 0) {
			rule_vec_free(&rules);
			return err;
		}
	}

	err = save_rules(&rules);
	rule_vec_free(&rules);
	return err;
}

static int cmd_rule_delete(int argc, char **argv)
{
	struct nl4_rule_vec rules;
	struct in_addr remote_addr;
	uint8_t service_side;
	uint16_t service_port;
	ssize_t idx;
	int err;

	err = parse_delete_args(argc, argv, &remote_addr, &service_side,
				&service_port);
	if (err < 0)
		return err;

	err = load_rules(&rules);
	if (err < 0)
		return err;

	idx = find_rule_index(&rules, &remote_addr, service_side, service_port);
	if (idx < 0) {
		rule_vec_free(&rules);
		return -ESRCH;
	}

	memmove(&rules.items[idx], &rules.items[idx + 1],
		(rules.len - (size_t)idx - 1) * sizeof(rules.items[0]));
	rules.len--;
	err = save_rules(&rules);
	rule_vec_free(&rules);
	return err;
}

static int cmd_rule_flush(void)
{
	struct nl4_rule_vec rules = { 0 };

	return save_rules(&rules);
}

static int cmd_rule_list(void)
{
	struct nl4_rule_vec rules;
	size_t i;
	int err;

	err = load_rules(&rules);
	if (err < 0)
		return err;

	for (i = 0; i < rules.len; i++) {
		const struct nl4_rule_cfg *rule = &rules.items[i];
		char remote_ip[INET_ADDRSTRLEN];
		char src_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &rule->remote_addr, remote_ip,
			  sizeof(remote_ip));
		inet_ntop(AF_INET, &rule->src_addr, src_ip, sizeof(src_ip));
		if (rule->service_side == NL4_SERVICE_ALL_PORTS)
			printf("%s src=%s all-ports fp=%s\n", remote_ip, src_ip,
			       rule->key_fingerprint);
		else
			printf("%s src=%s %s=%u fp=%s\n", remote_ip, src_ip,
			       service_side_name(rule->service_side),
			       rule->service_port, rule->key_fingerprint);
	}

	rule_vec_free(&rules);
	return 0;
}

static int cmd_rule(int argc, char **argv)
{
	if (argc < 1)
		return -EINVAL;
	if (strcmp(argv[0], "add") == 0)
		return cmd_rule_add(argc - 1, argv + 1);
	if (strcmp(argv[0], "delete") == 0)
		return cmd_rule_delete(argc - 1, argv + 1);
	if (strcmp(argv[0], "list") == 0 && argc == 1)
		return cmd_rule_list();
	if (strcmp(argv[0], "flush") == 0 && argc == 1)
		return cmd_rule_flush();
	return -EINVAL;
}

static int cmd_apply(void)
{
	struct nl4_rule_vec rules;
	struct nl4_ctx ctx;
	size_t i;
	int err;

	err = load_rules(&rules);
	if (err < 0)
		return err;

	if (!module_is_loaded()) {
		rule_vec_free(&rules);
		return -ENOENT;
	}

	err = nl4_open(&ctx);
	if (err < 0) {
		rule_vec_free(&rules);
		nl4_close(&ctx);
		return err;
	}

	err = send_flush_cmd(&ctx);
	if (err < 0)
		goto out;

	for (i = 0; i < rules.len; i++) {
		const struct nl4_rule_cfg *rule = &rules.items[i];

		err = send_rule_cmd(&ctx, NL4_CMD_ADD_RULE,
				    rule->remote_addr.s_addr,
				    rule->service_side, rule->service_port,
				    rule->shared_key);
		if (err < 0)
			goto out;
	}

	printf("applied %zu rule%s\n", rules.len, rules.len == 1 ? "" : "s");

out:
	nl4_close(&ctx);
	rule_vec_free(&rules);
	return err;
}

static bool module_is_loaded(void)
{
	FILE *fp;
	char name[128];
	bool loaded = false;

	fp = fopen("/proc/modules", "r");
	if (!fp)
		return false;

	while (fscanf(fp, "%127s%*[^\n]\n", name) == 1) {
		if (strcmp(name, NL4_MODULE_NAME) == 0) {
			loaded = true;
			break;
		}
	}
	fclose(fp);
	return loaded;
}

static const char *find_module_path(void)
{
	static const char *paths[] = {
		"kmod/nl4_bypass.ko",
		"./nl4_bypass.ko",
		"../kmod/nl4_bypass.ko",
	};
	const char *env_path = getenv("NL4_MODULE_PATH");
	size_t i;

	if (env_path && access(env_path, R_OK) == 0)
		return env_path;
	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		if (access(paths[i], R_OK) == 0)
			return paths[i];
	}
	return NULL;
}

static int run_program(const char *path, char *const argv[])
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid == 0) {
		execvp(path, argv);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) < 0)
		return -errno;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return -EIO;

	return 0;
}

static int cmd_on(int argc, char **argv)
{
	bool do_apply = false;
	int err;

	if (argc > 1)
		return -EINVAL;
	if (argc == 1) {
		if (strcmp(argv[0], "--apply") != 0)
			return -EINVAL;
		do_apply = true;
	}

	if (module_is_loaded()) {
		printf("module already loaded\n");
		if (!do_apply)
			return 0;
	} else {
		const char *module_path = find_module_path();
		char *const insmod_argv[] = {
			"insmod",
			(char *)module_path,
			NULL,
		};

		if (!module_path) {
			fprintf(stderr, "nl4enc: module file not found; run make build-krn first\n");
			return NL4_ERR_QUIET;
		}
		err = run_program("insmod", insmod_argv);
		if (err < 0)
			return err;
		if (do_apply)
			printf("module loaded\n");
	}

	if (do_apply)
		return cmd_apply();

	printf("module loaded; run `nl4enc apply` to activate configured rules.\n");
	return 0;
}

static int cmd_stop(void)
{
	char *const rmmod_argv[] = {
		"rmmod",
		NL4_MODULE_NAME,
		NULL,
	};

	if (!module_is_loaded()) {
		printf("module not loaded\n");
		return 0;
	}

	return run_program("rmmod", rmmod_argv);
}

int main(int argc, char **argv)
{
	int err;

	if (argc < 2) {
		usage(stderr);
		return 2;
	}

	if (strcmp(argv[1], "rule") == 0)
		err = cmd_rule(argc - 2, argv + 2);
	else if (strcmp(argv[1], "apply") == 0 && argc == 2)
		err = cmd_apply();
	else if (strcmp(argv[1], "on") == 0)
		err = cmd_on(argc - 2, argv + 2);
	else if (strcmp(argv[1], "stop") == 0 && argc == 2)
		err = cmd_stop();
	else
		err = -EINVAL;

	if (err < 0) {
		if (err == -EINVAL)
			usage(stderr);
		else if (err != NL4_ERR_QUIET)
			print_error("nl4enc", err);
		return 1;
	}

	return 0;
}
