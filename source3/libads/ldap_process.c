/*
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Uri Simchoni <urisimchoni@gmail.com> 2015

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "ads.h"

#ifdef HAVE_LDAP

/**
 * @file ldap_process.c
 * @brief LDAP query result processing methods
 *
 **/

struct ads_callback_process_ctx {
	ads_ldap_msg_process_fn fn;
	void *data;
};

static ADS_STATUS ads_callback_process_msg(struct ads_search_ctx *_ctx,
					   ADS_STRUCT *ads, LDAPMessage *msg,
					   bool *cont);

static struct ads_search_process_ops callback_ops = {
    .name = "callback", .process_msg = ads_callback_process_msg};

ADS_STATUS ads_create_callback_process_context(TALLOC_CTX *mem_ctx,
					       ads_ldap_msg_process_fn fn,
					       void *data,
					       struct ads_search_ctx *_ctx)
{
	struct ads_callback_process_ctx *ctx =
	    talloc_zero(mem_ctx, struct ads_callback_process_ctx);
	if (ctx == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	ctx->fn = fn;
	ctx->data = data;

	_ctx->process_ops = &callback_ops;
	_ctx->process_ctx = ctx;

	return ADS_SUCCESS;
}

static ADS_STATUS ads_callback_process_msg(struct ads_search_ctx *_ctx,
					   ADS_STRUCT *ads, LDAPMessage *msg,
					   bool *cont)
{
	struct ads_callback_process_ctx *ctx = talloc_get_type_abort(
	    _ctx->process_ctx, struct ads_callback_process_ctx);
	ads_process_results(ads, msg, ctx->fn, ctx->data);
	ldap_msgfree(msg);
	*cont = true;

	return ADS_SUCCESS;
}

#endif
