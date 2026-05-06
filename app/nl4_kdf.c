#include "nl4_kdf.h"

#include <errno.h>
#include <openssl/evp.h>
#include <string.h>

#define NL4_SALT_PREFIX "nl4enc-v1"

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

int nl4_parse_hex_exact(const char *hex, uint8_t *out, size_t out_len)
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

void nl4_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
	static const char table[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		hex[i * 2] = table[bytes[i] >> 4];
		hex[i * 2 + 1] = table[bytes[i] & 0xf];
	}
	hex[len * 2] = '\0';
}

void nl4_make_fingerprint(const uint8_t key[NL4_SHARED_KEY_LEN],
			  char fingerprint[SHA256_DIGEST_LENGTH + 1])
{
	uint8_t digest[SHA256_DIGEST_LENGTH];

	SHA256(key, NL4_SHARED_KEY_LEN, digest);
	nl4_bytes_to_hex(digest, 8, fingerprint);
}

void nl4_make_salt(const struct in_addr *src_addr,
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

int nl4_derive_psk_key(const char *psk, const uint8_t *salt, size_t salt_len,
		       uint8_t key[NL4_SHARED_KEY_LEN])
{
	if (!PKCS5_PBKDF2_HMAC(psk, (int)strlen(psk), salt, (int)salt_len,
			       NL4_DEFAULT_KDF_ITERATIONS, EVP_sha256(),
			       NL4_SHARED_KEY_LEN, key))
		return -EINVAL;

	return 0;
}
