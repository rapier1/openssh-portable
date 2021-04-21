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

#if defined(BOOHAVE_EVP_CHACHA20) && !defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include <openssl/evp.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"
#include "thread_pool.h"

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
	const u_char *key;
	int keylen;
};

struct chachathread {
	u_int index;
	u_char *dest;
	const u_char *src;
	u_int startpos;
	u_int len;
	u_int aadlen;
	u_int curpos;
	u_int offset;
	pthread_t tid;
	u_char seqbuf[16];
	struct chachapoly_ctx *ctx;
	int ctx_init;
	int response;
} chachathread;

static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static CRYPTO_RWLOCK *cryptolock;

//int total = 0;
//int joined = 0;
pthread_mutex_t lock;
pthread_cond_t cond;
int tcount = 0;
void *thpool = NULL;

static void myinit(void) {
	cryptolock = CRYPTO_THREAD_lock_new();
}

static int mylock(void) {
	if (!CRYPTO_THREAD_run_once(&once, *myinit) || cryptolock == NULL)
		return 0;
	return CRYPTO_THREAD_write_lock(cryptolock);
}

static int myunlock(void) {
	return CRYPTO_THREAD_unlock(cryptolock);
}

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
	ctx->key = key;
	ctx->keylen = keylen;
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
}

/* threaded function */
void *chachapoly_thread_work(void *thread) {
	//total++;
	struct chachathread *lt = (struct chachathread *)thread;
	void *ret;
	int val = 0;
	//fprintf(stderr, "Made thread!\n");
	//for (int i = 0; i < 4; i++)
	//	fprintf(stderr, "index %d: seqbuf[%d] = %x\n", lt->index, i, lt->seqbuf[i]); 
	fprintf(stderr, "index: %d startpos: %d len: %d tid: %ld\n", lt->index, lt->startpos, lt->len, lt->tid);
	if (mylock()) {
		if (!EVP_CipherInit(lt->ctx->main_evp, NULL, NULL, lt->seqbuf, 1) ||
		    EVP_Cipher(lt->ctx->main_evp, lt->dest,
			       lt->src + lt->offset, lt->len) < 0) {
			fprintf(stderr, "Crypto error in thread %d\n", lt->index);
			exit(-1);
		}
		//fprintf (stderr, "Chunk finished\n");
		myunlock();
	} else {
		fprintf (stderr, "FAILED TO GET CRYPTO LOCK\n");
	}
	
	if (val < 0) {
		exit(-1);
		fprintf(stderr, "Fail cipher\n");
		lt->response = SSH_ERR_LIBCRYPTO_ERROR;
		//ret = SSH_ERR_LIBCRYPTO_ERROR;
	}
	//fprintf(stderr, "thread: tcount: %d\n", tcount);
	explicit_bzero(lt->seqbuf, sizeof(lt->seqbuf));
	tcount--;
	//__sync_fetch_and_sub(&tcount,1);
	//fprintf(stderr, "TCOUNT is %d\n", tcount);
	pthread_exit(ret);
	//return NULL;
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
	struct chachathread thread[16];
	//pthread_mutex_init(&lock, NULL);
	
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

	//fprintf(stderr, "1: len = %d, aadlen = %d seqnr= %d\n", len, aadlen, seqnr);
	
	/* max len of the inbound data is 32k + 4. first pass break any len > 8192 into
	   chunks and submit each chunk to a new thread. */
	   
	/* 
	   basic premise. You have an inbound 'src' and an outbound 'dest'
	   src has the enclear data and dest holds the crypto data. Take the 
	   src data and break it down into chunks and process each of those chunk 
	   in parallel. The resulting crypto'd chunk can then just be slotted into 
	   dest at the appropriate byte location. 
	 */

	u_int chunk = 1024*64; /* cc20 block size is 64bytes */

	if (len >= chunk) { /* if the length of the inbound datagram is less than */
		            /* the chunk size don't bother with threading. */ 
		u_int bufptr = 0; // track where we are in the buffer
		int i = 0; // iterator

		while (bufptr < len) {
			//fprintf(stderr,"2: bufptr < len\n");
			//fprintf(stderr, "aad: %d Len: %d, Buffptr: %d, Chunk: %d Diff: %d\n",
			//aadlen, len, bufptr, chunk, (len-bufptr));
			//pthread_mutex_lock(&lock);
			if (thread[i].ctx_init != 1) {
				thread[i].ctx = chachapoly_new(ctx->key, ctx->keylen);
				thread[i].ctx_init = 1;
			}
			memset(thread[i].seqbuf, 0, sizeof(seqbuf));
			POKE_U64(thread[i].seqbuf + 8, seqnr);
			//fprintf (stderr, "block count is %d\n", bufptr/64);
			if (bufptr == 0) {
				thread[i].seqbuf[0] = 1;
			} else {
				POKE_U32_LITTLE(thread[i].seqbuf, bufptr/64);
				//thread[i].seqbuf[0] = 1;
			}
			thread[i].startpos = bufptr;
			thread[i].offset = aadlen + bufptr;;
			if ((len - bufptr) >= chunk) {
				thread[i].len = chunk;
				thread[i].dest = calloc (chunk, sizeof(u_char));
				bufptr += chunk;
			} else {
				thread[i].len = len-bufptr;
				thread[i].dest = calloc (len, sizeof(u_char));
				bufptr = len;
			}
			thread[i].index = i;
			thread[i].src = src;
			tcount++;
			pthread_create(&thread[i].tid, NULL, chachapoly_thread_work, &thread[i]);
			i++;
			//pthread_mutex_unlock(&lock);
		} 
		int foo = 0;
		do {
			foo++;
			if (foo > 1000)
				tcount--;
			fprintf(stderr, "waiting %d for %d\n", tcount, foo);
			//__sync_synchronize();
		} while (tcount > 0);
		for (int k = 0; k < i; k++) {
			fprintf (stderr, "%d: index: %d, startpos: %d len: %d tid: %ld\n",
				 k, thread[k].index, thread[k].startpos, thread[k].len, thread[k].tid);
			memcpy(dest+aadlen+thread[k].startpos, thread[k].dest, thread[k].len);
			//free(thread[k].dest);
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
	//fprintf(stderr, "Exiting chunk loop\n");

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
	//fprintf(stderr, "Exiting function loop\n");	
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
