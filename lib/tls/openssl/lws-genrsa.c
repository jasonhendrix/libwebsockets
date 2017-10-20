/*
 * libwebsockets - generic RSA api hiding the backend
 *
 * Copyright (C) 2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  lws_genhash provides a hash / hmac abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "private-libwebsockets.h"

LWS_VISIBLE void
lws_jwk_destroy_genrsa_elements(struct lws_genrsa_elements *el)
{
	if (el->n.buf)
		lws_free_set_NULL(el->n.buf);
	if (el->e.buf)
		lws_free_set_NULL(el->e.buf);
	if (el->d.buf)
		lws_free_set_NULL(el->d.buf);
	if (el->p.buf)
		lws_free_set_NULL(el->p.buf);
	if (el->q.buf)
		lws_free_set_NULL(el->q.buf);
	if (el->dp.buf)
		lws_free_set_NULL(el->dp.buf);
	if (el->dq.buf)
		lws_free_set_NULL(el->dq.buf);
	if (el->qi.buf)
		lws_free_set_NULL(el->qi.buf);
}

LWS_VISIBLE int
lws_genrsa_create(struct lws_genrsa_ctx *ctx,
				 struct lws_genrsa_elements *el)
{
	memset(ctx, 0, sizeof(*ctx));

	/* Step 1:
	 *
	 * convert the MPI for e and n to OpenSSL BIGNUMs
	 */

	ctx->bn_e = BN_bin2bn(el->e.buf, el->e.len, NULL);
	if (!ctx->bn_e) {
		lwsl_notice("mpi load E failed\n");
		return 1;
	}

	ctx->bn_n = BN_bin2bn(el->n.buf, el->n.len, NULL);
	if (!ctx->bn_n) {
		lwsl_notice("mpi load N failed\n");
		goto bail_n;
	}

	if (el->d.buf) {
		ctx->bn_d = BN_bin2bn(el->d.buf, el->d.len, NULL);
		if (!ctx->bn_d) {
			lwsl_notice("mpi load D failed\n");
			goto bail_d;
		}
	}

	if (el->p.buf) {
		ctx->bn_p = BN_bin2bn(el->p.buf, el->p.len, NULL);
		if (!ctx->bn_p) {
			lwsl_notice("mpi load P failed\n");
			goto bail_p;
		}
	}

	if (el->q.buf) {
		ctx->bn_q = BN_bin2bn(el->q.buf, el->q.len, NULL);
		if (!ctx->bn_q) {
			lwsl_notice("mpi load Q failed\n");
			goto bail_q;
		}
	}

	/* Step 2:
	 *
	 * assemble the OpenSSL RSA from the BIGNUMs
	 */

	ctx->rsa = RSA_new();
	if (!ctx->rsa) {
		lwsl_notice("Failed to create RSA\n");
		goto bail;
	}
#if defined(LWS_HAVE_RSA_SET0_KEY)
	if (RSA_set0_key(ctx->rsa, ctx->bn_n, ctx->bn_e, ctx->bn_d) != 1) {
		lwsl_notice("RSA_set0_key failed\n");
		RSA_free(ctx->rsa);
		goto bail;
	}
	RSA_set0_factors(ctx->rsa, ctx->bn_p, ctx->bn_q);
#else
	ctx->rsa->e = ctx->bn_e;
	ctx->rsa->n = ctx->bn_n;
	ctx->rsa->d = ctx->bn_d;
	ctx->rsa->p = ctx->bn_p;
	ctx->rsa->q = ctx->bn_q;
#endif

	return 0;

bail:
	BN_free(ctx->bn_q);
	ctx->bn_q = NULL;
bail_q:
	BN_free(ctx->bn_p);
	ctx->bn_p = NULL;
bail_p:
	BN_free(ctx->bn_d);
	ctx->bn_d = NULL;
bail_d:
	BN_free(ctx->bn_n);
	ctx->bn_n = NULL;
bail_n:
	BN_free(ctx->bn_e);
	ctx->bn_e = NULL;

	return 1;
}

LWS_VISIBLE int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	uint32_t m;

	m = RSA_public_decrypt(in_len, in, out, ctx->rsa, RSA_PKCS1_PADDING);

	/* the bignums are also freed by freeing the RSA */
	RSA_free(ctx->rsa);
	ctx->rsa = NULL;

	if (m != (uint32_t)-1)
		return (int)m;

	return -1;
}

static int
lws_genrsa_genrsa_hash_to_NID(enum lws_genhash_types hash_type)
{
	int h = -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
		h = NID_sha1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = NID_sha256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = NID_sha384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = NID_sha512;
		break;
	}

	return h;
}

LWS_VISIBLE int
lws_genrsa_public_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n = lws_genrsa_genrsa_hash_to_NID(hash_type),
	    h = lws_genhash_size(hash_type);

	if (n < 0)
		return -1;

	n = RSA_verify(n, in, h, (uint8_t *)sig, sig_len, ctx->rsa);
	if (n != 1) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_genrsa_public_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, uint8_t *sig,
			 size_t sig_len)
{
	int n = lws_genrsa_genrsa_hash_to_NID(hash_type),
	    h = lws_genhash_size(hash_type);
	unsigned int used = 0;

	if (n < 0)
		return -1;

	n = RSA_sign(n, in, h, (uint8_t *)sig, &used, ctx->rsa);
	if (n != 1) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return used;
}

LWS_VISIBLE void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	if (!ctx->rsa)
		return;

#if defined(LWS_HAVE_RSA_SET0_KEY)
	if (RSA_set0_key(ctx->rsa, NULL, NULL, NULL) != 1)
		lwsl_notice("RSA_set0_key failed\n");
	RSA_set0_factors(ctx->rsa, NULL, NULL);

#else
	ctx->rsa->e = NULL;
	ctx->rsa->n = NULL;
	ctx->rsa->d = NULL;
	ctx->rsa->p = NULL;
	ctx->rsa->q = NULL;
#endif

	RSA_free(ctx->rsa);

	ctx->rsa = NULL;
}
