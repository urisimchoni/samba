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
 * @file ldap_ctrl.c
 * @brief Helper functions for creating and analyzing LDAP controls
 *        and retrieval policies
 *
 **/

struct vlv_retrv_ctx {
	char *sort_attr;
	uint32_t from;
	uint32_t count;
	uint32_t table_size;
	uint32_t search_err;
	DATA_BLOB context;
};

static ADS_STATUS ads_vlv_build_controls(struct ads_search_ctx *ctx,
					 ADS_STRUCT *ads,
					 LDAPControl ***scontrols);
static ADS_STATUS ads_vlv_cont(struct ads_search_ctx *ctx, ADS_STRUCT *ads,
			       LDAPControl **rcontrols, bool *cont);

static struct ads_search_retrv_ops vlv_retrv_ops = {
    .name = "VLV",
    .build_controls = ads_vlv_build_controls,
    .cont = ads_vlv_cont,
};

static LDAPControl no_referrals = {
    .ldctl_oid = discard_const_p(char, ADS_NO_REFERRALS_OID),
    .ldctl_iscritical = 0,
    .ldctl_value.bv_len = 0,
    .ldctl_value.bv_val = discard_const_p(char, ""),
};

static int ads_free_controls(LDAPControl **controls)
{
	int i;
	/* first one is the no-referrals */
	for (i = 1; controls[i] != NULL; ++i) {
		ldap_control_free(controls[i]);
	}

	return 0;
}

ADS_STATUS ads_create_vlv_retrieval_context(
    TALLOC_CTX *mem_ctx, const char *sort_attr, uint32_t from, uint32_t count,
    uint32_t table_size, DATA_BLOB context, struct ads_search_ctx *_ctx)
{
	struct vlv_retrv_ctx *ctx;

	/* Sanity */
	if (count == 0) {
		DEBUG(0, ("Invalid count - 0\n"));
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	if (from == 0) {
		DEBUG(0, ("Invalid from - 0 - this API is 1-based\n"));
		return ADS_ERROR_NT(NT_STATUS_INVALID_PARAMETER);
	}

	ctx = talloc_zero(mem_ctx, struct vlv_retrv_ctx);
	if (!ctx) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	ctx->sort_attr = talloc_strdup(ctx, sort_attr);
	if (!ctx->sort_attr) {
		TALLOC_FREE(ctx);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	ctx->from = from;
	ctx->count = count;
	ctx->table_size = table_size;
	ctx->context = data_blob_dup_talloc(ctx, context);
	if (context.data && !ctx->context.data) {
		TALLOC_FREE(ctx);
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	_ctx->retrv_ops = &vlv_retrv_ops;
	_ctx->retrieval_ctx = ctx;

	return ADS_SUCCESS;
}

static ADS_STATUS ads_vlv_build_controls(struct ads_search_ctx *_ctx,
					 ADS_STRUCT *ads,
					 LDAPControl ***scontrols)
{
	struct vlv_retrv_ctx *ctx =
	    talloc_get_type_abort(_ctx->retrieval_ctx, struct vlv_retrv_ctx);
	int rc;
	LDAPSortKey **sort_keys = NULL;
	LDAPVLVInfo vlvinfo;
	struct berval vlv_context;
	LDAPControl **controls = NULL;

	controls = talloc_zero_array(ctx, LDAPControl *, 4);

	if (controls == NULL) {
		return ADS_ERROR(LDAP_NO_MEMORY);
	}

	talloc_set_destructor(controls, ads_free_controls);

	controls[0] = &no_referrals;

	/* The Sort control */
	rc = ldap_create_sort_keylist(&sort_keys, ctx->sort_attr);
	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("creation of sort key list (%s) failed - %s\n",
			  ctx->sort_attr, ldap_err2string(rc)));
		goto done;
	}

	rc = ldap_create_sort_control(ads->ldap.ld, sort_keys, 1, &controls[1]);
	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("creation of sort control (%s) failed - %s\n",
			  ctx->sort_attr, ldap_err2string(rc)));
		goto done;
	}

	/* The VLV control */
	ZERO_STRUCT(vlvinfo);
	vlvinfo.ldvlv_version = 1;
	vlvinfo.ldvlv_before_count = 0;
	vlvinfo.ldvlv_after_count = ctx->count - 1;
	vlvinfo.ldvlv_offset = ctx->from;
	if (ctx->from > 1) {
		vlvinfo.ldvlv_count = ctx->table_size;
	} else {
		vlvinfo.ldvlv_count = ctx->count;
	}
	vlv_context.bv_val = (char *)ctx->context.data;
	vlv_context.bv_len = ctx->context.length;
	vlvinfo.ldvlv_context = &vlv_context;

	rc = ldap_create_vlv_control(ads->ldap.ld, &vlvinfo, &controls[2]);
	if (rc != LDAP_SUCCESS) {
		DEBUG(0, ("creation of vlv control (%u, %u, %u, [%p, %zu]) "
			  "failed - %s\n",
			  ctx->from, ctx->count, ctx->table_size,
			  ctx->context.data, ctx->context.length,
			  ldap_err2string(rc)));
		goto done;
	}

	*scontrols = controls;
	controls = NULL;
	ctx->search_err = 0;

done:
	if (sort_keys)
		ldap_free_sort_keylist(sort_keys);

	TALLOC_FREE(controls);

	return ADS_ERROR(rc);
}

static ADS_STATUS ads_vlv_cont(struct ads_search_ctx *_ctx, ADS_STRUCT *ads,
			       LDAPControl **rcontrols, bool *cont)
{
	struct vlv_retrv_ctx *ctx =
	    talloc_get_type_abort(_ctx->retrieval_ctx, struct vlv_retrv_ctx);
	struct berval *context_bv = NULL;
	int rc = LDAP_CONTROL_NOT_FOUND, i;
	ber_int_t target_pos, list_count, errcode;

	data_blob_free(&ctx->context);

	/* default - MAY retry on failure */
	*cont = true;

	for (i = 0; rcontrols[i]; ++i) {
		rc = ldap_parse_vlvresponse_control(ads->ldap.ld, rcontrols[i],
						    &target_pos, &list_count,
						    &context_bv, &errcode);

		if (rc != LDAP_SUCCESS && rc != LDAP_CONTROL_NOT_FOUND) {
			DEBUG(
			    1,
			    ("Failed parsing LDAP control with oid %s. rc=%d\n",
			     rcontrols[i]->ldctl_oid, rc));
			break;
		}
	}

	if (rc != LDAP_SUCCESS) {
		DEBUG(3, ("Failed parsing VLV return control - tried %d "
			  "controls and got %d\n",
			  i, rc));
		goto done;
	}

	if (context_bv) {
		ctx->context = data_blob_talloc(ctx, context_bv->bv_val,
						context_bv->bv_len);
		if (!ctx->context.data) {
			DEBUG(
			    0,
			    ("failed duplicating %zd bytes of search context\n",
			     (size_t)context_bv->bv_len));
			rc = LDAP_NO_MEMORY;
			/* internal error - do not even retry */
			*cont = false;
			goto done;
		}
	}

	ctx->from = target_pos;
	ctx->table_size = list_count;
	ctx->search_err = errcode;

	if (ctx->search_err != 0) {
		DEBUG(3, ("server vlv query failed with code of %d\n",
			  ctx->search_err));
		/* Hmmmm... return error or success?
		 * The argument for success is better layering -
		 * search_err consulted only upon success.
		 * The advantage of error is ability to retry
		 * (or maybe retry should not be done?)
		 */
	}

	/* success - do not perform more
	   query */
	*cont = false;

done:
	if (context_bv)
		ber_bvfree(context_bv);

	return ADS_ERROR(rc);
}

void ads_recv_vlv_retrieval_context(struct ads_search_ctx *_ctx,
				    DATA_BLOB *search_context, uint32_t *from,
				    uint32_t *table_size, uint32_t *error_code)
{
	struct vlv_retrv_ctx *ctx =
	    talloc_get_type_abort(_ctx->retrieval_ctx, struct vlv_retrv_ctx);

	if (search_context) {
		*search_context = ctx->context;
	}

	if (from) {
		*from = ctx->from;
	}

	if (table_size) {
		*table_size = ctx->table_size;
	}

	if (error_code) {
		*error_code = ctx->search_err;
	}
}
#endif
