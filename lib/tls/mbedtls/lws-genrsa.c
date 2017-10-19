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
	ctx->ctx = lws_zalloc(sizeof(*ctx->ctx), "genrsa");
	if (!ctx->ctx)
		return 1;

	mbedtls_rsa_init(ctx->ctx, MBEDTLS_RSA_PKCS_V15, 0);

	if (el->e.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->E, el->e.buf, el->e.len)) {
		lwsl_notice("mpi load E failed\n");
		return 1;
	}
	if (el->n.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->N, el->n.buf, el->n.len)) {
		lwsl_notice("mpi load N failed\n");
		return 1;
	}
	if (el->d.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->D, el->d.buf, el->d.len)) {
		lwsl_notice("mpi load D failed\n");
		return 1;
	}
	if (el->p.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->P, el->p.buf, el->p.len)) {
		lwsl_notice("mpi load P failed\n");
		return 1;
	}
	if (el->q.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->Q, el->q.buf, el->q.len)) {
		lwsl_notice("mpi load Q failed\n");
		return 1;
	}
	if (el->dp.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->DP, el->dp.buf, el->dp.len)) {
		lwsl_notice("mpi load DP failed\n");
		return 1;
	}
	if (el->dq.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->DQ, el->dq.buf, el->dq.len)) {
		lwsl_notice("mpi load DQ failed\n");
		return 1;
	}
	if (el->qi.buf &&
	    mbedtls_mpi_read_binary(&ctx->ctx->QP, el->qi.buf, el->qi.len)) {
		lwsl_notice("mpi load QP failed\n");
		return 1;
	}

	ctx->ctx->len = el->n.len;

	return 0;
}

LWS_VISIBLE int
lws_genrsa_public_decrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out, size_t out_max)
{
	size_t olen = 0;
	int n;

	ctx->ctx->len = in_len;
	n = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx->ctx, NULL, NULL,
						MBEDTLS_RSA_PUBLIC,
						&olen, in, out, out_max);
	if (n) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return olen;
}

LWS_VISIBLE int
lws_genrsa_public_encrypt(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			   size_t in_len, uint8_t *out)
{
	int n;

	ctx->ctx->len = in_len;
	n = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx->ctx, NULL, NULL,
						MBEDTLS_RSA_PRIVATE,
						in_len, in, out);
	if (n) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return 0;
}

static int
lws_genrsa_genrsa_hash_to_mbed_hash(enum lws_genhash_types hash_type)
{
	int h = -1;

	switch (hash_type) {
	case LWS_GENHASH_TYPE_SHA1:
		h = MBEDTLS_MD_SHA1;
		break;
	case LWS_GENHASH_TYPE_SHA256:
		h = MBEDTLS_MD_SHA256;
		break;
	case LWS_GENHASH_TYPE_SHA384:
		h = MBEDTLS_MD_SHA384;
		break;
	case LWS_GENHASH_TYPE_SHA512:
		h = MBEDTLS_MD_SHA512;
		break;
	}

	return h;
}

LWS_VISIBLE int
lws_genrsa_public_verify(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, const uint8_t *sig,
			 size_t sig_len)
{
	int n, h = lws_genrsa_genrsa_hash_to_mbed_hash(hash_type);

	if (h < 0)
		return -1;

	n = mbedtls_rsa_rsassa_pkcs1_v15_verify(ctx->ctx, NULL, NULL,
						MBEDTLS_RSA_PUBLIC,
						h, 0, in, sig);
	if (n < 0) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return n;
}

LWS_VISIBLE int
lws_genrsa_public_sign(struct lws_genrsa_ctx *ctx, const uint8_t *in,
			 enum lws_genhash_types hash_type, uint8_t *sig,
			 size_t sig_len)
{
	int n, h = lws_genrsa_genrsa_hash_to_mbed_hash(hash_type);

	if (h < 0)
		return -1;

	/*
	 * The "sig" buffer must be as large as the size of ctx->N
	 * (eg. 128 bytes if RSA-1024 is used).
	 */
	if (sig_len < ctx->ctx->len)
		return -1;

	n = mbedtls_rsa_rsassa_pkcs1_v15_sign(ctx->ctx, NULL, NULL,
					      MBEDTLS_RSA_PRIVATE, h, 0, in,
					      sig);
	if (n < 0) {
		lwsl_notice("%s: -0x%x\n", __func__, -n);

		return -1;
	}

	return ctx->ctx->len;
}

LWS_VISIBLE void
lws_genrsa_destroy(struct lws_genrsa_ctx *ctx)
{
	mbedtls_rsa_free(ctx->ctx);
	lws_free(ctx->ctx);
}
