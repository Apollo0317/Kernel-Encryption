/**
 * @Author: Apollo
*/

#include "nl4_common.h"
#include "nl4_config.h"
#include "nl4_genl.h"
#include "nl4_kdf.h"
#include "nl4_module.h"
#include "nl4_route.h"

#include <errno.h>
#include <netlink/errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
			if (nl4_parse_hex_exact(argv[++i], args->key,
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
		err = nl4_infer_src_ip(&args.remote_addr, &args.src_addr);
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
		nl4_make_salt(&rule.src_addr, &rule.remote_addr, rule.salt,
			      &rule.salt_len);
		err = nl4_derive_psk_key(args.psk, rule.salt, rule.salt_len,
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
	nl4_make_fingerprint(rule.shared_key, rule.key_fingerprint);

	err = nl4_load_rules(&rules);
	if (err < 0)
		return err;

	idx = nl4_find_rule_index(&rules, &rule.remote_addr, rule.service_side,
				  rule.service_port);
	if (idx >= 0 && !args.replace) {
		nl4_rule_vec_free(&rules);
		return -EEXIST;
	}
	if (idx >= 0) {
		rules.items[idx] = rule;
	} else {
		err = nl4_rule_vec_push(&rules, &rule);
		if (err < 0) {
			nl4_rule_vec_free(&rules);
			return err;
		}
	}

	err = nl4_save_rules(&rules);
	nl4_rule_vec_free(&rules);
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

	err = nl4_load_rules(&rules);
	if (err < 0)
		return err;

	idx = nl4_find_rule_index(&rules, &remote_addr, service_side,
				  service_port);
	if (idx < 0) {
		nl4_rule_vec_free(&rules);
		return -ESRCH;
	}

	memmove(&rules.items[idx], &rules.items[idx + 1],
		(rules.len - (size_t)idx - 1) * sizeof(rules.items[0]));
	rules.len--;
	err = nl4_save_rules(&rules);
	nl4_rule_vec_free(&rules);
	return err;
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
		return nl4_config_list();
	if (strcmp(argv[0], "flush") == 0 && argc == 1)
		return nl4_config_flush();
	return -EINVAL;
}

static int cmd_apply(void)
{
	struct nl4_rule_vec rules;
	struct nl4_ctx ctx;
	size_t i;
	int err;

	err = nl4_load_rules(&rules);
	if (err < 0)
		return err;

	if (!nl4_module_is_loaded()) {
		nl4_rule_vec_free(&rules);
		return -ENOENT;
	}

	err = nl4_genl_open(&ctx);
	if (err < 0) {
		nl4_rule_vec_free(&rules);
		nl4_genl_close(&ctx);
		return err;
	}

	err = nl4_genl_flush_rules(&ctx);
	if (err < 0)
		goto out;

	for (i = 0; i < rules.len; i++) {
		err = nl4_genl_add_rule(&ctx, &rules.items[i]);
		if (err < 0)
			goto out;
	}

	printf("applied %zu rule%s\n", rules.len, rules.len == 1 ? "" : "s");

out:
	nl4_genl_close(&ctx);
	nl4_rule_vec_free(&rules);
	return err;
}

static int cmd_on(int argc, char **argv)
{
	bool do_apply = false;

	if (argc > 1)
		return -EINVAL;
	if (argc == 1) {
		if (strcmp(argv[0], "--apply") != 0)
			return -EINVAL;
		do_apply = true;
	}

	return nl4_module_on(do_apply, cmd_apply);
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
		err = nl4_module_stop();
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
