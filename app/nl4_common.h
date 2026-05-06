#ifndef NL4_COMMON_H
#define NL4_COMMON_H

#include <arpa/inet.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>

#include <nl4_netlink.h>

#define NL4_CONFIG_DIR "/etc/nl4enc"
#define NL4_RULES_PATH NL4_CONFIG_DIR "/rules.json"
#define NL4_RULES_TMP_PATH NL4_CONFIG_DIR "/rules.json.tmp"
#define NL4_MODULE_NAME "nl4_bypass"
#define NL4_DEFAULT_KDF_ITERATIONS 200000
#define NL4_KDF_VERSION "pbkdf2-hmac-sha256-v1"
#define NL4_RAW_KEY_VERSION "raw-key-v1"
#define NL4_MAX_SALT_LEN 64
#define NL4_ERR_QUIET (-100000)

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

const char *nl4_service_side_name(uint8_t side);
int nl4_parse_service_side_name(const char *name, uint8_t *side);

#endif
