#ifndef NL4_KDF_H
#define NL4_KDF_H

#include "nl4_common.h"

int nl4_parse_hex_exact(const char *hex, uint8_t *out, size_t out_len);
void nl4_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex);
void nl4_make_fingerprint(const uint8_t key[NL4_SHARED_KEY_LEN],
			  char fingerprint[SHA256_DIGEST_LENGTH + 1]);
void nl4_make_salt(const struct in_addr *src_addr,
		   const struct in_addr *remote_addr,
		   uint8_t salt[NL4_MAX_SALT_LEN], size_t *salt_len);
int nl4_derive_psk_key(const char *psk, const uint8_t *salt, size_t salt_len,
		       uint8_t key[NL4_SHARED_KEY_LEN]);

#endif
