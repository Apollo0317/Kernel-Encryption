#include "nl4_config.h"

#include "nl4_kdf.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void nl4_rule_vec_free(struct nl4_rule_vec *rules)
{
	free(rules->items);
	rules->items = NULL;
	rules->len = 0;
	rules->cap = 0;
}

int nl4_rule_vec_push(struct nl4_rule_vec *rules,
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

ssize_t nl4_find_rule_index(const struct nl4_rule_vec *rules,
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
	    nl4_parse_service_side_name(service_side, &rule->service_side) < 0 ||
	    port > 65535 ||
	    nl4_parse_hex_exact(shared_key_hex, rule->shared_key,
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
	    nl4_parse_hex_exact(salt_hex, rule->salt, rule->salt_len) < 0)
		return -EINVAL;

	return 0;
}

int nl4_load_rules(struct nl4_rule_vec *rules)
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
		    nl4_rule_vec_push(rules, &rule) < 0) {
			err = -EINVAL;
			break;
		}
		p = obj_end + 1;
	}

	free(buf);
	if (err < 0)
		nl4_rule_vec_free(rules);
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

int nl4_save_rules(const struct nl4_rule_vec *rules)
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
		nl4_bytes_to_hex(rule->shared_key, sizeof(rule->shared_key),
				 shared_key_hex);
		nl4_bytes_to_hex(rule->salt, rule->salt_len, salt_hex);

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
			remote_ip, src_ip, nl4_service_side_name(rule->service_side),
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

int nl4_config_flush(void)
{
	struct nl4_rule_vec rules = { 0 };

	return nl4_save_rules(&rules);
}

int nl4_config_list(void)
{
	struct nl4_rule_vec rules;
	size_t i;
	int err;

	err = nl4_load_rules(&rules);
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
			       nl4_service_side_name(rule->service_side),
			       rule->service_port, rule->key_fingerprint);
	}

	nl4_rule_vec_free(&rules);
	return 0;
}
