/*
 * Authentication
 */

#include <stdlib.h>
#include <assert.h>
#include <openssl/evp.h>
#include "config.h"
#include "amidi2net.h"

/* Generate 16byte crypto nonce */
/* FIXME: not really recommended, just for PoC */
void generate_crypto_nonce(unsigned char *buf)
{
	int i;

	/* use ASCII letters between 32 and 126 */
	for (i = 0; i < 16; i++)
		buf[i] = random() % (126 - 32 + 1) + 32;
}

int auth_sha256_digest(unsigned char *buf,
		       const unsigned char *nonce,
		       const unsigned char *secret,
		       int secret_len)
{
	EVP_MD_CTX *ctx;
	unsigned int out_len;

	ctx = EVP_MD_CTX_create();
	if (!ctx)
		return -1;
	EVP_DigestInit(ctx, EVP_MD_fetch(NULL, "SHA256", NULL));
	EVP_DigestUpdate(ctx, nonce, 16);
	EVP_DigestUpdate(ctx, secret, secret_len);
	EVP_DigestFinal(ctx, buf, &out_len);
	EVP_MD_CTX_destroy(ctx);
	assert(out_len == 32);
	return 0;
}

int user_auth_sha256_digest(unsigned char *buf,
			    const unsigned char *nonce,
			    const unsigned char *user,
			    int user_len,
			    const unsigned char *passwd,
			    int passwd_len)
{
	EVP_MD_CTX *ctx;
	unsigned int out_len;

	ctx = EVP_MD_CTX_create();
	if (!ctx)
		return -1;
	EVP_DigestInit(ctx, EVP_MD_fetch(NULL, "SHA256", NULL));
	EVP_DigestUpdate(ctx, nonce, 16);
	EVP_DigestUpdate(ctx, user, user_len);
	EVP_DigestUpdate(ctx, passwd, passwd_len);
	EVP_DigestFinal(ctx, buf, &out_len);
	EVP_MD_CTX_destroy(ctx);
	assert(out_len == 32);
	return 0;
}
