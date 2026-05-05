
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/jhash.h>
#include <linux/percpu.h>
#include <linux/bottom_half.h>
#include <linux/minmax.h>
#include <crypto/chacha.h>
#include "nl4_utility.h"

u32 IP2NUM(const char *addr)
{
	return in_aton(addr);
}

inline void NUM2IP(u32 addr, char *str)
{
    snprintf(str, 16, "%pI4", &addr);
}

/***************proto define***************/
static unsigned int test_skcipher_encdec(struct skcipher_def *sk, int enc);
static void test_skcipher_cb(void *data, int error);
static struct crypto_skcipher *nl4_alloc_stream_cipher(void);
static int nl4_skcipher_crypt(char *data, unsigned int data_len, int enc,
			      const char *cipher_name, const u8 *iv,
			      unsigned int expected_ivsize);

struct nl4_tcp_crypto_ctx {
	u8 stream[CHACHA_BLOCK_SIZE];
};

static DEFINE_PER_CPU(struct nl4_tcp_crypto_ctx, nl4_tcp_ctx);

/* Callback function */
static void test_skcipher_cb(void *data, int error)
{
	struct tcrypt_result *result = data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	//pr_info("Encryption finished successfully\n");
}

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct skcipher_def *sk,
					 int enc)
{
	int rc = 0;

	if (enc)
		rc = crypto_skcipher_encrypt(sk->req);
	else
		rc = crypto_skcipher_decrypt(sk->req);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		rc = wait_for_completion_interruptible(
			&sk->result.completion);
		if (rc)
			break;
		if (sk->result.err) {
			rc = sk->result.err;
			break;
		}
		reinit_completion(&sk->result.completion);
		break;
	default:
		//pr_info("skcipher encrypt returned with %d result %d\n", rc, sk->result.err);
		break;
	}
	init_completion(&sk->result.completion);

	return rc;
}

static struct crypto_skcipher *nl4_alloc_stream_cipher(void)
{
	struct crypto_skcipher *skcipher;

	skcipher = crypto_alloc_skcipher("chacha20", 0, 0);
	if (!IS_ERR(skcipher))
		return skcipher;

	pr_info("chacha20 unavailable, falling back to ctr(aes)\n");
	return crypto_alloc_skcipher("ctr(aes)", 0, 0);
}

static int nl4_skcipher_crypt(char *data, unsigned int data_len, int enc,
			      const char *cipher_name, const u8 *iv,
			      unsigned int expected_ivsize)
{
	struct skcipher_def sk;
	struct crypto_skcipher *skcipher = NULL;
	struct skcipher_request *req = NULL;
	char *ivdata = NULL;
	unsigned char key[32];
	unsigned int ivsize;
	int ret = -EFAULT;

	if (data_len == 0)
		return 0;

	if (cipher_name)
		skcipher = crypto_alloc_skcipher(cipher_name, 0, 0);
	else
		/* Prefer a true stream cipher and keep payload length unchanged. */
		skcipher = nl4_alloc_stream_cipher();
	if (IS_ERR(skcipher)) {
		pr_info("could not allocate stream cipher handle\n");
		return PTR_ERR(skcipher);
	}

	req = skcipher_request_alloc(skcipher, GFP_KERNEL);
	if (!req) {
		pr_info("could not allocate skcipher request\n");
		ret = -ENOMEM;
		goto out;
	}

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      test_skcipher_cb,
				      &sk.result);

	memset(key, 1, sizeof(key));
	if (crypto_skcipher_setkey(skcipher, key, 32)) {
		pr_info("key could not be set\n");
		ret = -EAGAIN;
		goto out;
	}

	ivsize = crypto_skcipher_ivsize(skcipher);
	if (expected_ivsize && ivsize != expected_ivsize) {
		pr_info("unexpected ivsize %u for %s\n", ivsize, cipher_name);
		ret = -EINVAL;
		goto out;
	}
	if (ivsize != 0) {
		ivdata = kzalloc(ivsize, GFP_KERNEL);
	}
	if (ivsize != 0 && !ivdata) {
		pr_info("could not allocate ivdata\n");
		ret = -ENOMEM;
		goto out;
	}
	if (iv && ivsize)
		memcpy(ivdata, iv, ivsize);

	sk.tfm = skcipher;
	sk.req = req;
	sk.result.err = 0;
	init_completion(&sk.result.completion);

	sg_init_one(&sk.sg, data, data_len);
	skcipher_request_set_crypt(req, &sk.sg, &sk.sg, data_len, ivdata);
	ret = test_skcipher_encdec(&sk, enc);
	
out:
	if (skcipher)
		crypto_free_skcipher(skcipher);
	if (req)
		skcipher_request_free(req);
	if (ivdata)
		kfree(ivdata);
	return ret;
}

int nl4_crypto_cipher(char *data, __u16 data_len, int enc)
{
	return nl4_skcipher_crypt(data, data_len, enc, NULL, NULL, 0);
}

int nl4_tcp_crypto_cipher(char *data, unsigned int data_len,
			  const struct iphdr *iph, const struct tcphdr *tcph,
			  const u32 key_words[CHACHA_KEY_SIZE / sizeof(u32)],
			  int enc)
{
	struct nl4_tcp_crypto_ctx *ctx;
	u32 state[CHACHA_STATE_WORDS];
	u32 tuple[5];
	u32 nonce[3];
	u32 tcp_seq;
	u32 block_index;
	unsigned int done = 0;
	unsigned int skip;

	if (data_len == 0)
		return 0;

	tcp_seq = ntohl(tcph->seq);
	block_index = tcp_seq / CHACHA_BLOCK_SIZE;
	skip = tcp_seq % CHACHA_BLOCK_SIZE;

	tuple[0] = (__force u32)iph->saddr;
	tuple[1] = (__force u32)iph->daddr;
	tuple[2] = ((__force u32)tcph->source << 16) | (__force u32)tcph->dest;
	tuple[3] = iph->protocol;
	tuple[4] = 0x4e4c3454;
	nonce[0] = jhash2(tuple, ARRAY_SIZE(tuple), 0x6e6c3461);
	nonce[1] = jhash2(tuple, ARRAY_SIZE(tuple), 0x6e6c3462);
	nonce[2] = jhash2(tuple, ARRAY_SIZE(tuple), 0x6e6c3463);

	chacha_init_consts(state);
	memcpy(&state[4], key_words, CHACHA_KEY_SIZE);
	state[12] = block_index;
	state[13] = nonce[0];
	state[14] = nonce[1];
	state[15] = nonce[2];

	local_bh_disable();
	ctx = this_cpu_ptr(&nl4_tcp_ctx);

	while (done < data_len) {
		unsigned int block_off = (done == 0) ? skip : 0;
		unsigned int todo = min_t(unsigned int, data_len - done,
					  CHACHA_BLOCK_SIZE - block_off);
		unsigned int i;

		chacha_block_generic(state, ctx->stream, 20);
		for (i = 0; i < todo; i++)
			data[done + i] ^= ctx->stream[block_off + i];
		done += todo;
	}

	local_bh_enable();
	return 0;
}

int nl4_crypto_init(void)
{
	return 0;
}

void nl4_crypto_exit(void)
{
}
