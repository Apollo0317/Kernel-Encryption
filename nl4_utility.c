
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/slab.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/jhash.h>
#include <linux/percpu.h>
#include <linux/spinlock.h>
#include <asm/unaligned.h>
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
	struct skcipher_request *req;
	struct scatterlist sg;
	struct tcrypt_result result;
	u8 iv[CHACHA_IV_SIZE];
	u8 *scratch;
	spinlock_t lock;
};

static struct crypto_skcipher *nl4_tcp_skcipher;
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

static int nl4_tcp_skcipher_crypt(struct nl4_tcp_crypto_ctx *ctx,
				  unsigned int crypt_len, int enc)
{
	int rc;

	ctx->result.err = 0;
	init_completion(&ctx->result.completion);
	sg_init_one(&ctx->sg, ctx->scratch, crypt_len);
	skcipher_request_set_crypt(ctx->req, &ctx->sg, &ctx->sg, crypt_len,
				   ctx->iv);

	if (enc)
		rc = crypto_skcipher_encrypt(ctx->req);
	else
		rc = crypto_skcipher_decrypt(ctx->req);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		rc = -EAGAIN;
		break;
	default:
		break;
	}

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
			  int enc)
{
	struct nl4_tcp_crypto_ctx *ctx;
	u32 tuple[5];
	u32 nonce[3];
	u32 tcp_seq;
	u32 block_index;
	unsigned int skip;
	unsigned int crypt_len;
	unsigned int cpu;
	int ret;

	if (data_len == 0)
		return 0;
	if (!nl4_tcp_skcipher)
		return -ENODEV;

	tcp_seq = ntohl(tcph->seq);
	block_index = tcp_seq / CHACHA_BLOCK_SIZE;
	skip = tcp_seq % CHACHA_BLOCK_SIZE;
	crypt_len = data_len + skip;
	if (unlikely(crypt_len > NL4_TCP_SCRATCH_SIZE))
		return -EMSGSIZE;

	cpu = get_cpu();
	ctx = per_cpu_ptr(&nl4_tcp_ctx, cpu);
	put_cpu();
	spin_lock_bh(&ctx->lock);
	memset(ctx->scratch, 0, skip);
	memcpy(ctx->scratch + skip, data, data_len);

	tuple[0] = (__force u32)iph->saddr;
	tuple[1] = (__force u32)iph->daddr;
	tuple[2] = ((__force u32)tcph->source << 16) | (__force u32)tcph->dest;
	tuple[3] = iph->protocol;
	tuple[4] = 0x4e4c3454;
	nonce[0] = jhash2(tuple, ARRAY_SIZE(tuple), 0x6e6c3461);
	nonce[1] = jhash2(tuple, ARRAY_SIZE(tuple), 0x6e6c3462);
	nonce[2] = jhash2(tuple, ARRAY_SIZE(tuple), 0x6e6c3463);

	put_unaligned_le32(block_index, ctx->iv);
	put_unaligned_le32(nonce[0], ctx->iv + 4);
	put_unaligned_le32(nonce[1], ctx->iv + 8);
	put_unaligned_le32(nonce[2], ctx->iv + 12);

	ret = nl4_tcp_skcipher_crypt(ctx, crypt_len, enc);
	if (ret == 0)
		memcpy(data, ctx->scratch + skip, data_len);

	spin_unlock_bh(&ctx->lock);
	return ret;
}

int nl4_crypto_init(void)
{
	unsigned char key[CHACHA_KEY_SIZE];
	unsigned int cpu;
	int ret = 0;

	nl4_tcp_skcipher = crypto_alloc_skcipher("chacha20", 0,
						 CRYPTO_ALG_ASYNC);
	if (IS_ERR(nl4_tcp_skcipher)) {
		ret = PTR_ERR(nl4_tcp_skcipher);
		pr_err("could not allocate TCP chacha20 handle: %d\n", ret);
		nl4_tcp_skcipher = NULL;
		return ret;
	}

	if (crypto_skcipher_ivsize(nl4_tcp_skcipher) != CHACHA_IV_SIZE) {
		pr_err("unexpected TCP chacha20 ivsize %u\n",
		       crypto_skcipher_ivsize(nl4_tcp_skcipher));
		ret = -EINVAL;
		goto err;
	}

	memset(key, 1, sizeof(key));
	ret = crypto_skcipher_setkey(nl4_tcp_skcipher, key, sizeof(key));
	if (ret) {
		pr_err("could not set TCP chacha20 key: %d\n", ret);
		goto err;
	}

	for_each_possible_cpu(cpu) {
		struct nl4_tcp_crypto_ctx *ctx = per_cpu_ptr(&nl4_tcp_ctx, cpu);

		spin_lock_init(&ctx->lock);
		ctx->scratch = kmalloc(NL4_TCP_SCRATCH_SIZE, GFP_KERNEL);
		if (!ctx->scratch) {
			ret = -ENOMEM;
			goto err;
		}
		ctx->req = skcipher_request_alloc(nl4_tcp_skcipher, GFP_KERNEL);
		if (!ctx->req) {
			ret = -ENOMEM;
			goto err;
		}
		skcipher_request_set_callback(ctx->req,
					      CRYPTO_TFM_REQ_MAY_BACKLOG,
					      test_skcipher_cb, &ctx->result);
		init_completion(&ctx->result.completion);
	}

	return 0;

err:
	nl4_crypto_exit();
	return ret;
}

void nl4_crypto_exit(void)
{
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		struct nl4_tcp_crypto_ctx *ctx = per_cpu_ptr(&nl4_tcp_ctx, cpu);

		if (ctx->req) {
			skcipher_request_free(ctx->req);
			ctx->req = NULL;
		}
		kfree(ctx->scratch);
		ctx->scratch = NULL;
	}

	if (nl4_tcp_skcipher) {
		crypto_free_skcipher(nl4_tcp_skcipher);
		nl4_tcp_skcipher = NULL;
	}
}
