/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $OpenBSD: cipher-chachapoly-libcrypto.c,v 1.1 2020/04/03 04:32:21 djm Exp $ */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <openssl/evp.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"
#include "pthread_pool.h"

#define POKE_U32_LITTLE(p, v)			\
        do { \
                const u_int32_t __v = (v); \
		((u_char *)(p))[3] = (__v >> 24) & 0xff; \
                ((u_char *)(p))[2] = (__v >> 16) & 0xff; \
                ((u_char *)(p))[1] = (__v >> 8) & 0xff; \
                ((u_char *)(p))[0] = __v & 0xff; \
        } while (0)

struct chachapoly_ctx {
	EVP_CIPHER_CTX *main_evp, *header_evp;
	const u_char *key; /* pointer to key to pass to job's ctx init*/
	int keylen;
	int reset; /* has the cipher been reset with new keys */
};

struct chachajob {
	u_char *dest; /* pointer to dest */
	const u_char *src; /* pointer to source */
	u_int len; /* length of src/dest chunk */
	u_int offset; /* position within src and dest */
	u_char seqbuf[16]; /* need a unique seqbuf for each job */
	struct chachapoly_ctx *ctx; /* and its own cipher ctx */
	int free_ctx; /* do we need to free this ctx when asked? */
} chachajob;

void *thpool = NULL;
#define MAX_JOBS 12
struct chachajob ccjob[MAX_JOBS];

struct chachapoly_ctx *
chachapoly_new(const u_char *key, u_int keylen)
{
	struct chachapoly_ctx *ctx;

	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		return NULL;
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;
	if ((ctx->main_evp = EVP_CIPHER_CTX_new()) == NULL ||
	    (ctx->header_evp = EVP_CIPHER_CTX_new()) == NULL)
		goto fail;
	if (!EVP_CipherInit(ctx->main_evp, EVP_chacha20(), key, NULL, 1))
		goto fail;
	if (!EVP_CipherInit(ctx->header_evp, EVP_chacha20(), key + 32, NULL, 1))
		goto fail;
	if (EVP_CIPHER_CTX_iv_length(ctx->header_evp) != 16)
		goto fail;
	ctx->key = key;       /* we need to get the key to the thread ctxs so */
	ctx->keylen = keylen; /* we do it this way don't know how I feel about it */ 
	ctx->reset = 1;       /* it's just a pointer but still */
	return ctx;
fail:
	chachapoly_free(ctx);
	return NULL;
}

void
chachapoly_free(struct chachapoly_ctx *cpctx)
{
	if (cpctx == NULL)
		return;
	EVP_CIPHER_CTX_free(cpctx->main_evp);
	EVP_CIPHER_CTX_free(cpctx->header_evp);
	freezero(cpctx, sizeof(*cpctx));
	/* we want to free the job ctxs but only 
	 * if they've been instantiated. This doesn't happen
	 * with each chachapoly_free() call so we track it 
	 * with the free_ctx flag */
	for (int i = 0; i < MAX_JOBS; i++) {
		if (ccjob[i].free_ctx == 1) {
			EVP_CIPHER_CTX_free(ccjob[i].ctx->main_evp);
			EVP_CIPHER_CTX_free(ccjob[i].ctx->header_evp);
			freezero(ccjob[i].ctx, sizeof(*cpctx));
			ccjob[i].free_ctx = 0;
		}
	}
}

/* threaded function */
void *chachapoly_thread_work(void *job) {
	struct chachajob *lt = (struct chachajob *)job;
	if (!EVP_CipherInit(lt->ctx->main_evp, NULL, NULL, lt->seqbuf, 1) ||
	    EVP_Cipher(lt->ctx->main_evp, lt->dest + lt->offset,
		       lt->src + lt->offset, lt->len) < 0)
	{
		/* is there anything more we can tell the user? */
		fatal("Threaded Chacha20 libcrypto error.");
	}
	explicit_bzero(lt->seqbuf, sizeof(lt->seqbuf));
	return NULL;
}

/*
 * chachapoly_crypt() operates as following:
 * En/decrypt with header key 'aadlen' bytes from 'src', storing result
 * to 'dest'. The ciphertext here is treated as additional authenticated
 * data for MAC calculation.
 * En/decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'. Use
 * POLY1305_TAGLEN bytes at offset 'len'+'aadlen' as the authentication
 * tag. This tag is written on encryption and verified on decryption.
 */
int
chachapoly_crypt(struct chachapoly_ctx *ctx, u_int seqnr, u_char *dest,
    const u_char *src, u_int len, u_int aadlen, u_int authlen, int do_encrypt)
{
	u_char seqbuf[16]; /* layout: u64 counter || u64 seqno */
	int r = SSH_ERR_INTERNAL_ERROR;
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
	u_int chunk = 64*64; /* cc20 block size is 64 bytes */

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(seqbuf, 0, sizeof(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	memset(poly_key, 0, sizeof(poly_key));
	if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1) ||
	    EVP_Cipher(ctx->main_evp, poly_key,
	    poly_key, sizeof(poly_key)) < 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* If decrypting, check tag before anything else */
	if (!do_encrypt) {
		const u_char *tag = src + aadlen + len;
		poly1305_auth(expected_tag, src, aadlen + len, poly_key);
		if (timingsafe_bcmp(expected_tag, tag, POLY1305_TAGLEN) != 0) {
			r = SSH_ERR_MAC_INVALID;
			goto out;
		}
	}

	/* Crypt additional data */
	if (aadlen) {
	  if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 1) ||
		    EVP_Cipher(ctx->header_evp, dest, src, aadlen) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}

	/*
	   basic premise. You have an inbound 'src' and an outbound 'dest'
	   src has the enclear data and dest holds the crypto data. Take the
	   src data and break it down into chunks and process each of those chunk
	   in parallel. The resulting crypto'd chunk can then just be slotted into
	   dest at the appropriate byte location.
	 */

	if (len >= chunk) { /* if the length of the inbound datagram is less than */
		            /* the chunk size don't bother with threading. */
		u_int bufptr = 0; // track where we are in the buffer
		int i = 0; // iterator

		if (thpool == NULL) {
			thpool = pool_start(chachapoly_thread_work, 4);
		}

		/* when ctx is reset with a new key we need to
		 * reinit the ctxs we are using in the jobs
		 * NB: CTX reset is true when we first need to
		 * init these.
		 */
		if (ctx->reset) {
			for (int j = 0; j < MAX_JOBS; j++) {
				ccjob[j].ctx = chachapoly_new(ctx->key, ctx->keylen);
				ccjob[j].free_ctx = 1;
				/* init seqbuf to 0 */
				memset(ccjob[j].seqbuf, 0, sizeof(seqbuf));
			}
			ctx->reset = 0;
		}

		while (bufptr < len) {
			POKE_U64(ccjob[i].seqbuf + 8, seqnr);
			POKE_U32_LITTLE(ccjob[i].seqbuf, (bufptr/64) + 1);
			ccjob[i].offset = aadlen + bufptr;
			if ((len - bufptr) >= chunk) {
				ccjob[i].len = chunk;
				bufptr += chunk;
			} else {
				ccjob[i].len = len-bufptr;
				bufptr = len;
			}
			ccjob[i].src = src;
			ccjob[i].dest = dest;
			pool_enqueue(thpool, &ccjob[i]);
			i++;
			/* somehow the number of chunks exceeded the number of 
			 * available jobs for the queue. Increase the size of the
			 * chunk or MAX_JOBS */
			if (i >= MAX_JOBS) {
				fatal("Threaded chacha tried to spawn too many jobs\n");
			}
		}
		while (pool_count(thpool)) {
			/* sit and spin */
		}
	} else { /*non threaded cc20 method*/
		seqbuf[0] = 1; // set the cc20 sequence counter to 1
		if (!EVP_CipherInit(ctx->main_evp, NULL, NULL, seqbuf, 1)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		if (EVP_Cipher(ctx->main_evp, dest + aadlen, src + aadlen, len) < 0) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
	}
	/* If encrypting, calculate and append tag */
	if (do_encrypt) {
		poly1305_auth(dest + aadlen + len, dest, aadlen + len,
		    poly_key);
	}
	r = 0;
 out:
	explicit_bzero(expected_tag, sizeof(expected_tag));
	explicit_bzero(seqbuf, sizeof(seqbuf));
	explicit_bzero(poly_key, sizeof(poly_key));
	return r;
}

/* Decrypt and extract the encrypted packet length */
int
chachapoly_get_length(struct chachapoly_ctx *ctx,
    u_int *plenp, u_int seqnr, const u_char *cp, u_int len)
{
	u_char buf[4], seqbuf[16];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	memset(seqbuf, 0, sizeof(seqbuf));
	POKE_U64(seqbuf + 8, seqnr);
	if (!EVP_CipherInit(ctx->header_evp, NULL, NULL, seqbuf, 0))
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (EVP_Cipher(ctx->header_evp, buf, (u_char *)cp, sizeof(buf)) < 0)
		return SSH_ERR_LIBCRYPTO_ERROR;
	*plenp = PEEK_U32(buf);
	return 0;
}
#endif /* defined(HAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20) */
