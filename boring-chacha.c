/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

// Adapted from the public domain, estream code by D. Bernstein.

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <omp.h>
#include "boring-chacha.h"

#define U8TO32_LITTLE(p)			      \
	(((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) |	\
	 ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))

// sigma contains the ChaCha constants, which happen to be an ASCII string.
static const uint8_t sigma[16] = { 'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
	'2', '-', 'b', 'y', 't', 'e', ' ', 'k' };

#define ROTATE(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

// QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round.
#define QUARTERROUND(a, b, c, d)			\
	x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a], 16);	\
	x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c], 12);	\
	x[a] += x[b]; x[d] = ROTATE(x[d] ^ x[a],  8);	\
	x[c] += x[d]; x[b] = ROTATE(x[b] ^ x[c],  7);

static inline int buffers_alias(const uint8_t *a, size_t a_len,
                                const uint8_t *b, size_t b_len) {
  // Cast |a| and |b| to integers. In C, pointer comparisons between unrelated
  // objects are undefined whereas pointer to integer conversions are merely
  // implementation-defined. We assume the implementation defined it in a sane
  // way.
  uintptr_t a_u = (uintptr_t)a;
  uintptr_t b_u = (uintptr_t)b;
  return a_u + a_len > b_u && b_u + b_len > a_u;
}

#define U32TO8_LITTLE(p, v)    \
	{		       \
		(p)[0] = (v >> 0) & 0xff;	\
		(p)[1] = (v >> 8) & 0xff;	\
		(p)[2] = (v >> 16) & 0xff;	\
		(p)[3] = (v >> 24) & 0xff;	\
	}


/* always expecting to get a 256 bit key */
void
chacha_keysetup(struct chacha_ctx *x, const uint8_t *key)
{
	x->input[0] = U8TO32_LITTLE(sigma + 0);
	x->input[1] = U8TO32_LITTLE(sigma + 4);
	x->input[2] = U8TO32_LITTLE(sigma + 8);
	x->input[3] = U8TO32_LITTLE(sigma + 12);
	x->input[4] = U8TO32_LITTLE(key + 0);
	x->input[5] = U8TO32_LITTLE(key + 4);
	x->input[6] = U8TO32_LITTLE(key + 8);
	x->input[7] = U8TO32_LITTLE(key + 12);
	key += 16;
	x->input[8] = U8TO32_LITTLE(key + 0);
	x->input[9] = U8TO32_LITTLE(key + 4);
	x->input[10] = U8TO32_LITTLE(key + 8);
	x->input[11] = U8TO32_LITTLE(key + 12);
}

void
chacha_ivsetup(struct chacha_ctx *x, const uint8_t *nonce, const uint8_t *counter)
{
	x->input[12] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 0);
	x->input[13] = counter == NULL ? 0 : U8TO32_LITTLE(counter + 4);
	x->input[14] = U8TO32_LITTLE(nonce + 0);
	x->input[15] = U8TO32_LITTLE(nonce + 4);
}



// chacha_core performs 20 rounds of ChaCha on the input words in
// |input| and writes the 64 output bytes to |output|.
/* we are using this implementation because stripping the core out
 * may allow us to use OpenMP to parallelize some of the process.
 */
static void chacha_core(uint8_t output[64], struct chacha_ctx *cc_ctx) {
	uint32_t x[16];
	int i;
	
	x[0] = cc_ctx->input[0];
	x[1] = cc_ctx->input[1];
	x[2] = cc_ctx->input[2];
	x[3] = cc_ctx->input[3];
	x[4] = cc_ctx->input[4];
	x[5] = cc_ctx->input[5];
	x[6] = cc_ctx->input[6];
	x[7] = cc_ctx->input[7];
	x[8] = cc_ctx->input[8];
	x[9] = cc_ctx->input[9];
	x[10] = cc_ctx->input[10];
	x[11] = cc_ctx->input[11];
	x[12] = cc_ctx->input[12];
	x[13] = cc_ctx->input[13];
	x[14] = cc_ctx->input[14];
	x[15] = cc_ctx->input[15];
	
	for (i = 20; i > 0; i -= 2) {
		QUARTERROUND(0, 4, 8, 12);
		QUARTERROUND(1, 5, 9, 13);
		QUARTERROUND(2, 6, 10, 14);
		QUARTERROUND(3, 7, 11, 15);
		QUARTERROUND(0, 5, 10, 15);
		QUARTERROUND(1, 6, 11, 12);
		QUARTERROUND(2, 7, 8, 13);
		QUARTERROUND(3, 4, 9, 14);
	}
	
	/* initially the following two sections were loops
	 * which is easier to read but incurs overhead due to
	 * the increment and conditional */
	x[0] += cc_ctx->input[0];
	x[1] += cc_ctx->input[1];
	x[2] += cc_ctx->input[2];
	x[3] += cc_ctx->input[3];
	x[4] += cc_ctx->input[4];
	x[5] += cc_ctx->input[5];
	x[6] += cc_ctx->input[6];
	x[7] += cc_ctx->input[7];
	x[8] += cc_ctx->input[8];
	x[9] += cc_ctx->input[9];
	x[10] += cc_ctx->input[10];
	x[11] += cc_ctx->input[11];
	x[12] += cc_ctx->input[12];
	x[13] += cc_ctx->input[13];
	x[14] += cc_ctx->input[14];
	x[15] += cc_ctx->input[15];

	U32TO8_LITTLE(output, x[0]);
	U32TO8_LITTLE(output + 4, x[1]);
	U32TO8_LITTLE(output + 8, x[2]);
	U32TO8_LITTLE(output + 12, x[3]);
	U32TO8_LITTLE(output + 16, x[4]);
	U32TO8_LITTLE(output + 20, x[5]);
	U32TO8_LITTLE(output + 24, x[6]);
	U32TO8_LITTLE(output + 28, x[7]);
	U32TO8_LITTLE(output + 32, x[8]);
	U32TO8_LITTLE(output + 36, x[9]);
	U32TO8_LITTLE(output + 40, x[10]);
	U32TO8_LITTLE(output + 44, x[11]);
	U32TO8_LITTLE(output + 48, x[12]);
	U32TO8_LITTLE(output + 52, x[13]);
	U32TO8_LITTLE(output + 56, x[14]);
	U32TO8_LITTLE(output + 60, x[15]);
}

static void chacha_core_omp(uint32_t *input, const uint8_t *in, uint8_t *out, int todo) {
	uint32_t x[16];
	uint8_t output[64];
	int i;
	int offset = 0;
	int step = (input[12] - 1) * 64; /* block counter - 1 gives us the correct
					  * position in the pointers to the input
					  * and output buffers */
	
	x[0] = input[0];
	x[1] = input[1];
	x[2] = input[2];
	x[3] = input[3];
	x[4] = input[4];
	x[5] = input[5];
	x[6] = input[6];
	x[7] = input[7];
	x[8] = input[8];
	x[9] = input[9];
	x[10] = input[10];
	x[11] = input[11];
	x[12] = input[12];
	x[13] = input[13];
	x[14] = input[14];
	x[15] = input[15];

	for (i = 20; i > 0; i -= 2) {
		QUARTERROUND(0, 4, 8, 12);
		QUARTERROUND(1, 5, 9, 13);
		QUARTERROUND(2, 6, 10, 14);
		QUARTERROUND(3, 7, 11, 15);
		QUARTERROUND(0, 5, 10, 15);
		QUARTERROUND(1, 6, 11, 12);
		QUARTERROUND(2, 7, 8, 13);
		QUARTERROUND(3, 4, 9, 14);
	}
	
	/* initially the following two sections were loops
	 * which is easier to read but incurs overhead due to
	 * the increment and conditional */
	x[0] += input[0];
	x[1] += input[1];
	x[2] += input[2];
	x[3] += input[3];
	x[4] += input[4];
	x[5] += input[5];
	x[6] += input[6];
	x[7] += input[7];
	x[8] += input[8];
	x[9] += input[9];
	x[10] += input[10];
	x[11] += input[11];
	x[12] += input[12];
	x[13] += input[13];
	x[14] += input[14];
	x[15] += input[15];
	
	U32TO8_LITTLE(output, x[0]);
	U32TO8_LITTLE(output + 4, x[1]);
	U32TO8_LITTLE(output + 8, x[2]);
	U32TO8_LITTLE(output + 12, x[3]);
	U32TO8_LITTLE(output + 16, x[4]);
	U32TO8_LITTLE(output + 20, x[5]);
	U32TO8_LITTLE(output + 24, x[6]);
	U32TO8_LITTLE(output + 28, x[7]);
	U32TO8_LITTLE(output + 32, x[8]);
	U32TO8_LITTLE(output + 36, x[9]);
	U32TO8_LITTLE(output + 40, x[10]);
	U32TO8_LITTLE(output + 44, x[11]);
	U32TO8_LITTLE(output + 48, x[12]);
	U32TO8_LITTLE(output + 52, x[13]);
	U32TO8_LITTLE(output + 56, x[14]);
	U32TO8_LITTLE(output + 60, x[15]);

       	for (int k = 0; k < todo; k++) {
		offset = k + step;
		out[offset] = in[offset] ^ output[k];
	}
}

/* take an input pointer (in) of in_len bytes and perform chacha_core on it
 * placing the results in the output pointer (out).
 */
void chacha_encrypt_bytes(struct chacha_ctx *cc_ctx, const uint8_t *in, uint8_t *out, size_t in_len)
{
	assert(!buffers_alias(out, in_len, in, in_len) || in == out);
	uint8_t buf[64];
	size_t todo, i;
	/* step through buffer in 64 byte chunks 
	 * decrement in_len until it reaches 0*/
	while (in_len > 0) {
		todo = sizeof(buf);
		/* less that 64 bytes remaining */
		if (in_len < todo) {
			todo = in_len;
		}

		/* this is where the magic happens */
		chacha_core(buf, cc_ctx);

		/* XOR the bytes 1 by 1 against the buffer returned by chacha core */
		/* can't unroll this as we don't know the size of todo */
		for (i = 0; i < todo; i++) {
			out[i] = in[i] ^ buf[i];
		}

		/* move memory by updating the position of the pointer*/
		out += todo;
		in += todo;
		/* decrement in_len*/
		in_len -= todo;

		/* increase the block counter by 1 */
		cc_ctx->input[12]++;
	}
}


/* take an input pointer (in) of in_len bytes and perform chacha_core on it
 * placing the results in the output pointer (out).
 */
void chacha_encrypt_bytes_omp(struct chacha_ctx *cc_ctx, const uint8_t *in, uint8_t *out, size_t in_len)
{
	assert(!buffers_alias(out, in_len, in, in_len) || in == out);
	size_t i;
	uint32_t cc_ctx_cpy[16];
	
	/* we need to make a copy of the cipher context */ 
	cc_ctx_cpy[0] = cc_ctx->input[0];
	cc_ctx_cpy[1] = cc_ctx->input[1];
	cc_ctx_cpy[2] = cc_ctx->input[2];
	cc_ctx_cpy[3] = cc_ctx->input[3];
	cc_ctx_cpy[4] = cc_ctx->input[4];
	cc_ctx_cpy[5] = cc_ctx->input[5];
	cc_ctx_cpy[6] = cc_ctx->input[6];
	cc_ctx_cpy[7] = cc_ctx->input[7];
	cc_ctx_cpy[8] = cc_ctx->input[8];
	cc_ctx_cpy[9] = cc_ctx->input[9];
	cc_ctx_cpy[10] = cc_ctx->input[10];
	cc_ctx_cpy[11] = cc_ctx->input[11];
	cc_ctx_cpy[12] = cc_ctx->input[12];
	cc_ctx_cpy[13] = cc_ctx->input[13];
	cc_ctx_cpy[14] = cc_ctx->input[14];
	cc_ctx_cpy[15] = cc_ctx->input[15];
	
	/* this is where the magic happens */
#pragma omp parallel for num_threads(4)
	/* copy the context as we can't share it 
	 * across threads */
	for (i = 0; i < in_len; i += 64) {
		int block_size = 64;
		int todo = 0;
		int counter = i/block_size + 1;
		int remaining = in_len - i;
		if (remaining > block_size) {
			todo = block_size;
		} else {
			todo = remaining;
		}
		/* set the block counter */
		cc_ctx_cpy[12] = counter;
		chacha_core_omp(cc_ctx_cpy, in, out, todo);
	}
}
