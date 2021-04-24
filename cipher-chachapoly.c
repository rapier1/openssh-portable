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

/* $OpenBSD: cipher-chachapoly.c,v 1.9 2020/04/03 04:27:03 djm Exp $ */

#include "includes.h"
#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"
#endif

#if !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20)

#include <sys/types.h>
#include <stdarg.h> /* needed for log.h */
#include <string.h>
#include <stdio.h>  /* needed for misc.h */

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "cipher-chachapoly.h"
#include "pthread.h"
#include "thpool.h"

#define POKE_U32_LITTLE(p, v)			\
        do { \
                const u_int32_t __v = (v); \
		((u_char *)(p))[3] = (__v >> 24) & 0xff; \
                ((u_char *)(p))[2] = (__v >> 16) & 0xff; \
                ((u_char *)(p))[1] = (__v >> 8) & 0xff; \
                ((u_char *)(p))[0] = __v & 0xff; \
        } while (0)

struct chachapoly_ctx {
	struct chacha_ctx main_ctx, header_ctx;
	const u_char *key;
	int keylen;
	int reset;
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
	u_char blk_ctr[8];
	u_char seqbuf[8];
	struct chachapoly_ctx *ctx;
	int ctxinit;
	int response;
	pthread_mutex_t tlock;
} chachathread;

pthread_mutex_t lock;
pthread_cond_t cond;
int tcount = 0;
void *thpool = NULL;
struct chachathread thread[15]; /* why 16? */
int MAX_THREADS = 16;

struct chachapoly_ctx *
chachapoly_new(const u_char *key, u_int keylen)
{
	struct chachapoly_ctx *ctx;

	if (keylen != (32 + 32)) /* 2 x 256 bit keys */
		return NULL;
	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return NULL;
	chacha_keysetup(&ctx->main_ctx, key, 256);
	chacha_keysetup(&ctx->header_ctx, key + 32, 256);
	ctx->key = key;
	ctx->keylen = keylen;
	ctx->reset = 1;
	return ctx;
}

void
chachapoly_free(struct chachapoly_ctx *cpctx)
{
	freezero(cpctx, sizeof(*cpctx));
}

/* threaded function */
void chachapoly_thread_work(void *thread) {
	struct chachathread *lt = (struct chachathread *)thread;
	//fprintf(stderr, "index[%d]: init cc iv with %d - %d\n",
	//	lt->index, lt->blk_ctr[0], lt->blk_ctr[1]);
	//pthread_mutex_lock(&lt->tlock);
	chacha_ivsetup(&lt->ctx->main_ctx, lt->seqbuf, lt->blk_ctr);	
	chacha_encrypt_bytes(&lt->ctx->main_ctx, lt->src + lt->offset, lt->dest + lt->offset, lt->len);
	__sync_fetch_and_sub(&tcount,1);
	//fprintf(stderr, "Tcount is %d for index[%d]\n", tcount, lt->index);
	//pthread_mutex_unlock(&lt->tlock);
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
	u_char seqbuf[8];
	const u_char one[8] = { 0, 0, 0, 0, 0, 0, 0, 0 }; /* NB little-endian */
	u_char expected_tag[POLY1305_TAGLEN], poly_key[POLY1305_KEYLEN];
	int r = SSH_ERR_INTERNAL_ERROR;
	u_int chunk = 128 * 64; /* 128 cc20 blocks */

	POKE_U32_LITTLE(one, 1);
	//fprintf (stderr, "Len: %d, aadlen %d, authlen %d\n", len, aadlen, authlen);

	/*
	 * Run ChaCha20 once to generate the Poly1305 key. The IV is the
	 * packet sequence number.
	 */
	memset(poly_key, 0, sizeof(poly_key));
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->main_ctx,
			     poly_key, poly_key, sizeof(poly_key));

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
		chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
		chacha_encrypt_bytes(&ctx->header_ctx, src, dest, aadlen);
	}

	/* initialize contexts for threads */
	/* if the key is changed we need to reinitialize the keys */
	if (ctx->reset == 1) {		
		for (int i = 0; i < MAX_THREADS; i++) {
			//pthread_mutex_init(&thread[i].tlock, NULL);
			fprintf(stderr, "Initializing thread[%d].ctx (keylen: %d]\n", i, ctx->keylen);
			thread[i].ctx = chachapoly_new(ctx->key, ctx->keylen);
		}
		ctx->reset = 0; /*reset complete */
	}

	/* Set Chacha's block counter to 1 */
	if (len > chunk) {
		u_int bufptr = 0;
		int i = 0;
		if (thpool == NULL) {
			fprintf(stderr, "initializing thread pool\n");
			thpool=thpool_init(3);
		}
		while (bufptr < len) {
			POKE_U32_LITTLE(thread[i].blk_ctr, (bufptr/64) +1);
			thread[i].startpos = bufptr;
			thread[i].offset = aadlen + bufptr;
			if ((len - bufptr) >= chunk) {
				thread[i].len = chunk;
				//thread[i].dest = calloc (chunk, sizeof(u_char));
				bufptr += chunk;
			} else {
				thread[i].len = len-bufptr;
				//thread[i].dest = calloc (len, sizeof(u_char));
				bufptr = len;
			}
			memset(thread[i].seqbuf, 0, sizeof(seqbuf));
			POKE_U64(thread[i].seqbuf, seqnr);
			//thread[i].ctx = ctx;
			thread[i].index = i;
			thread[i].src = src;
			thread[i].dest = dest;
			tcount++;
			//pthread_create(&thread[i].tid, NULL, chachapoly_thread_work, &thread[i]);
			thpool_add_work(thpool, chachapoly_thread_work, &thread[i]);
			i++;
		}
		/* int foo = 0; */
		/* do { */
		/* 	foo++; */
		/* 	__sync_synchronize(); */
		/* } while (tcount); */
		thpool_wait(thpool);
		
		/* for (int k = 0; k < i; k++) { */
		/* 	fprintf (stderr, "%d: index: %d, startpos: %d len: %d tid: %ld\n", */
		/* 		 k, thread[k].index, thread[k].startpos, thread[k].len, thread[k].tid); */
		/* 	memcpy(dest+aadlen+thread[k].startpos, thread[k].dest, thread[k].len); */
		/* 	free(thread[k].dest); */
		/* } */
		/* chacha_ivsetup(&ctx->main_ctx, seqbuf, one); */
		/* chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen, */
		/* 		     dest + aadlen, len); */

	} else {
		chacha_ivsetup(&ctx->main_ctx, seqbuf, one);
		chacha_encrypt_bytes(&ctx->main_ctx, src + aadlen,
				     dest + aadlen, len);
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
	u_char buf[4], seqbuf[8];

	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	POKE_U64(seqbuf, seqnr);
	chacha_ivsetup(&ctx->header_ctx, seqbuf, NULL);
	chacha_encrypt_bytes(&ctx->header_ctx, cp, buf, 4);
	*plenp = PEEK_U32(buf);
	return 0;
}

#endif /* !defined(HAVE_EVP_CHACHA20) || defined(HAVE_BROKEN_CHACHA20) */
