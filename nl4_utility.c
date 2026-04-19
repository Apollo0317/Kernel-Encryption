
#include <linux/string.h>
#include <linux/inet.h>
#include <linux/slab.h>
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
		if (!rc && !sk->result.err) {
			reinit_completion(&sk->result.completion);
			break;
		}
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

int nl4_crypto_cipher(char *data, __u16 data_len, int enc)
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
	if (ivsize != 0) {
		ivdata = kzalloc(ivsize, GFP_KERNEL);
	}
	if (ivsize != 0 && !ivdata) {
		pr_info("could not allocate ivdata\n");
		ret = -ENOMEM;
		goto out;
	}

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
