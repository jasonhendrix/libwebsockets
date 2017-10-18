/*
 * libwebsockets - JSON Web Key support
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
 */

#include "private-libwebsockets.h"
#include "../misc/lejp.h"

static const char * const jwk_tok[] = {
	"kty", "k", "n", "e", "d", "p", "q", "dp", "dq", "qi",
};
enum enum_jwk_tok {
	JWK_KTY,
	JWK_KEY,
	JWK_KEY_N,
	JWK_KEY_E,
	JWK_KEY_D,
	JWK_KEY_P,
	JWK_KEY_Q,
	JWK_KEY_DP,
	JWK_KEY_DQ,
	JWK_KEY_QI,
};

static int
_lws_jwk_set_element(struct lws_genrsa_element *e, char *in, int len)
{
	int dec_size = ((len * 3) / 4) + 4, n;

	e->buf = lws_malloc(dec_size, "jwk");
	if (!e->buf)
		return -1;

	n = lws_b64_decode_string_len(in, len, (char *)e->buf, dec_size - 1);
	if (n < 0)
		return -1;
	e->len = n;

	return 0;
}

struct cb_lws_jwk {
	struct lws_jwk *s;
	char *b64;
	int b64max;
	int pos;
};

static char
cb_jwk(struct lejp_ctx *ctx, char reason)
{
	struct cb_lws_jwk *cbs = (struct cb_lws_jwk *)ctx->user;
	struct lws_jwk *s = cbs->s;
	struct lws_genrsa_element *e;

	if (reason == LEJPCB_VAL_STR_START)
		cbs->pos = 0;

	if (!(reason & LEJP_FLAG_CB_IS_VALUE) || !ctx->path_match)
		return 0;

	switch (ctx->path_match - 1) {
	case JWK_KTY:
		strncpy(s->keytype, ctx->buf, sizeof(s->keytype) - 1);
		s->keytype[sizeof(s->keytype) - 1] = '\0';
		if (!strcmp(ctx->buf, "oct")) {
			break;
		}
		if (!strcmp(ctx->buf, "RSA")) {
			break;
		}
		return -1;

	case JWK_KEY:
		if (strcmp(s->keytype, "oct"))
			return -1;
		e = &s->el.e;
		goto read_element1;
	case JWK_KEY_N:
		e = &s->el.n;
		goto read_element;
	case JWK_KEY_E:
		e = &s->el.e;
		goto read_element;
	case JWK_KEY_D:
		e = &s->el.d;
		goto read_element;
	case JWK_KEY_P:
		e = &s->el.p;
		goto read_element;
	case JWK_KEY_Q:
		e = &s->el.q;
		goto read_element;
	case JWK_KEY_DP:
		e = &s->el.dp;
		goto read_element;
	case JWK_KEY_DQ:
		e = &s->el.dq;
		goto read_element;
	case JWK_KEY_QI:
		e = &s->el.qi;
		goto read_element;
	}

	return 0;

read_element:
	if (strcmp(s->keytype, "RSA"))
		return -1;

read_element1:

	if (cbs->pos + ctx->npos >= cbs->b64max)
		return -1;

	memcpy(cbs->b64 + cbs->pos, ctx->buf, ctx->npos);
	cbs->pos += ctx->npos;

	if (reason == LEJPCB_VAL_STR_CHUNK)
		return 0;

	if (_lws_jwk_set_element(e, cbs->b64, cbs->pos) < 0) {
		lws_jwk_destroy_genrsa_elements(&s->el);

		return -1;
	}

	return 0;
}

int
lws_jwk_create(struct lws_jwk *s, const char *in, size_t len)
{
	struct lejp_ctx jctx;
	struct cb_lws_jwk cbs;
	const int b64max = (((8192 / 8) * 4) / 3) + 1;  /* enough for 8K key */
	char b64[b64max];
	int m;

	memset(s, 0, sizeof(*s));
	cbs.s = s;
	cbs.b64 = b64;
	cbs.b64max = b64max;
	cbs.pos = 0;
	lejp_construct(&jctx, cb_jwk, &cbs, jwk_tok, ARRAY_SIZE(jwk_tok));
	m = (int)(signed char)lejp_parse(&jctx, (uint8_t *)in, len);
	lejp_destruct(&jctx);

	if (m < 0) {
		lwsl_notice("%s: parse got %d\n", __func__, m);

		return -1;
	}

	return 0;
}

void
lws_jwk_destroy(struct lws_jwk *s)
{
	lws_jwk_destroy_genrsa_elements(&s->el);
}
