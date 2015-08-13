/*
   Unix SMB/CIFS implementation.
   ads (active directory) utility library
   Copyright (C) Andrew Tridgell 2001
   Copyright (C) Remus Koos 2001
   Copyright (C) Jim McDonough <jmcd@us.ibm.com> 2002
   Copyright (C) Guenther Deschner 2005
   Copyright (C) Gerald Carter 2006

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

#ifndef _LIBADS_ADS_LDAP_PROTOS_H_
#define _LIBADS_ADS_LDAP_PROTOS_H_

#ifdef HAVE_LDAP_INIT_FD
int ldap_init_fd(ber_socket_t fd, int proto, char *uri, LDAP **ldp);
#endif

/*
 * Backend interface to generic LDAP search mechanism
 *
 * There seem to be a lot of variations on the basic LDAP search
 * theme:
 * - A search can consist of one query or multiple queries to
 *   obtain all results (using PagedControl)
 * - Virtual List View (VLV) control can be used to selectively
 *   retrieve part of the result set.
 * - In a multi-query search, result messages can be accumulated
 *   or processed one-by-one as they are retrieved.
 * - On failure, the operation can fail or retried by re-connecting
 *   to the AD server.
 * - Other LDAP controls can be added for backend processing.
 *
 * Supporting all those options and all their combinations leads to
 * a myriad of LDAP search functions and to duplication of code.
 *
 * To avoid that, we divide the various aspects of the search into
 * three facets:
 * 1. Retrieval policy (which contorl to use and how to use them)
 * 2. Processing policy (what to do with returned messages)
 * 3. Retry policy (whether or not to retry, how many retries)
 *
 * This division allows a mix-and-match of policies without
 * duplication of code. The interfaces below define how the
 * message processing policy and the retrieval policy talk to
 * the generic search function. Typical usage is:
 * 1. Construct retrieval policy and processing policy objects
 * 2. Call the generic search function ads_generic_search().
 *    ads_generic_search() converses with the policy objects
 *    and they also update their state according to search
 *    results.
 * 3. If needed, extract information from the policy objects
 *
 * For common uses (e.g. get all results with retry) a wrapper
 * can be made for this process for convenience.
**/

struct ads_search_ctx;

typedef bool (*ads_ldap_msg_process_fn)(ADS_STRUCT *, char *, void **, void *);

struct ads_search_process_ops {
	const char *name;
	ADS_STATUS (*process_msg)(struct ads_search_ctx *ctx, ADS_STRUCT *ads,
				  LDAPMessage *msg, bool *cont);
	void (*reset)(struct ads_search_ctx *ctx);
};

struct ads_search_retrv_ops {
	const char *name;
	ADS_STATUS (*build_controls)(struct ads_search_ctx *ctx,
				     ADS_STRUCT *ads, LDAPControl ***scontrols);
	ADS_STATUS (*cont)(struct ads_search_ctx *ctx, ADS_STRUCT *ads,
			   LDAPControl **rcontrols, bool *cont);
	void (*prepare_retry)(struct ads_search_ctx *ctx, ADS_STRUCT *ads,
			      ADS_STATUS last_error);
};

struct ads_search_ctx {
	struct ads_search_retrv_ops *retrv_ops;
	struct ads_search_process_ops *process_ops;
	void *retrieval_ctx;
	void *process_ctx;
	unsigned retries; /* after first attempt (0 -> no retry) */
};

#define ADS_SEARCH_DEFAULT_RETRIES 2

/*
 * Prototypes for ads
 */

LDAP *ldap_open_with_timeout(const char *server,
			     struct sockaddr_storage *ss,
			     int port, unsigned int to);
void ads_msgfree(ADS_STRUCT *ads, LDAPMessage *msg);
char *ads_get_dn(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, LDAPMessage *msg);

char *ads_pull_string(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx, LDAPMessage *msg,
		      const char *field);
char **ads_pull_strings(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
			LDAPMessage *msg, const char *field,
			size_t *num_values);
char **ads_pull_strings_range(ADS_STRUCT *ads,
			      TALLOC_CTX *mem_ctx,
			      LDAPMessage *msg, const char *field,
			      char **current_strings,
			      const char **next_attribute,
			      size_t *num_strings,
			      bool *more_strings);
bool ads_pull_uint32(ADS_STRUCT *ads, LDAPMessage *msg, const char *field,
		     uint32_t *v);
bool ads_pull_guid(ADS_STRUCT *ads, LDAPMessage *msg, struct GUID *guid);
bool ads_pull_sid(ADS_STRUCT *ads, LDAPMessage *msg, const char *field,
		  struct dom_sid *sid);
int ads_pull_sids(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		  LDAPMessage *msg, const char *field, struct dom_sid **sids);
bool ads_pull_sd(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
		 LDAPMessage *msg, const char *field, struct security_descriptor **sd);
char *ads_pull_username(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
			LDAPMessage *msg);
ADS_STATUS ads_find_machine_acct(ADS_STRUCT *ads, LDAPMessage **res,
				 const char *machine);
ADS_STATUS ads_find_printer_on_server(ADS_STRUCT *ads, LDAPMessage **res,
				      const char *printer,
				      const char *servername);
ADS_STATUS ads_find_printers(ADS_STRUCT *ads, LDAPMessage **res);
ADS_STATUS ads_find_user_acct(ADS_STRUCT *ads, LDAPMessage **res,
			      const char *user);

ADS_STATUS ads_do_search(ADS_STRUCT *ads, const char *bind_path, int scope,
			 const char *expr,
			 const char **attrs, LDAPMessage **res);
ADS_STATUS ads_search(ADS_STRUCT *ads, LDAPMessage **res,
		      const char *expr, const char **attrs);
ADS_STATUS ads_search_dn(ADS_STRUCT *ads, LDAPMessage **res,
			 const char *dn, const char **attrs);
ADS_STATUS ads_do_search_all_args(ADS_STRUCT *ads, const char *bind_path,
				  int scope, const char *expr,
				  const char **attrs, void *args,
				  LDAPMessage **res);
ADS_STATUS ads_do_search_all(ADS_STRUCT *ads, const char *bind_path,
			     int scope, const char *expr,
			     const char **attrs, LDAPMessage **res);
ADS_STATUS ads_do_search_retry(ADS_STRUCT *ads, const char *bind_path,
			       int scope,
			       const char *expr,
			       const char **attrs, LDAPMessage **res);
ADS_STATUS ads_search_retry(ADS_STRUCT *ads, LDAPMessage **res,
			    const char *expr, const char **attrs);
ADS_STATUS ads_search_retry_dn(ADS_STRUCT *ads, LDAPMessage **res,
			       const char *dn,
			       const char **attrs);
ADS_STATUS ads_search_retry_extended_dn_ranged(ADS_STRUCT *ads, TALLOC_CTX *mem_ctx,
						const char *dn,
						const char **attrs,
						enum ads_extended_dn_flags flags,
						char ***strings,
						size_t *num_strings);
ADS_STATUS ads_search_retry_sid(ADS_STRUCT *ads, LDAPMessage **res,
				const struct dom_sid *sid,
				const char **attrs);


LDAPMessage *ads_first_entry(ADS_STRUCT *ads, LDAPMessage *res);
LDAPMessage *ads_next_entry(ADS_STRUCT *ads, LDAPMessage *res);
LDAPMessage *ads_first_message(ADS_STRUCT *ads, LDAPMessage *res);
LDAPMessage *ads_next_message(ADS_STRUCT *ads, LDAPMessage *res);
void ads_process_results(ADS_STRUCT *ads, LDAPMessage *res,
			 bool (*fn)(ADS_STRUCT *,char *, void **, void *),
			 void *data_area);
void ads_dump(ADS_STRUCT *ads, LDAPMessage *res);

ADS_STATUS ads_generic_search(ADS_STRUCT *ads, const char *bind_path, int scope,
			      const char *expr, const char **attrs,
			      struct ads_search_ctx *search_ctx);
void ads_destroy_search_context(struct ads_search_ctx *search_ctx);
ADS_STATUS ads_create_accum_process_context(TALLOC_CTX *mem_ctx,
					    struct ads_search_ctx *ctx);
void ads_recv_accum_process_context(struct ads_search_ctx *ctx,
				    LDAPMessage **res);
ADS_STATUS ads_create_callback_process_context(TALLOC_CTX *mem_ctx,
					       ads_ldap_msg_process_fn fn,
					       void *data,
					       struct ads_search_ctx *ctx);
ADS_STATUS ads_create_vlv_retrieval_context(
    TALLOC_CTX *mem_ctx, const char *sort_attr, uint32_t from, uint32_t count,
    uint32_t table_size, DATA_BLOB context, struct ads_search_ctx *ctx);
void ads_recv_vlv_retrieval_context(struct ads_search_ctx *ctx,
				    DATA_BLOB *search_context, uint32_t *from,
				    uint32_t *table_size, uint32_t *error_code);
ADS_STATUS
ads_create_paged_retrieval_context(TALLOC_CTX *mem_ctx,
				   struct ads_search_ctx *ctx);

struct GROUP_POLICY_OBJECT;
ADS_STATUS ads_parse_gpo(ADS_STRUCT *ads,
			 TALLOC_CTX *mem_ctx,
			 LDAPMessage *res,
			 const char *gpo_dn,
			 struct GROUP_POLICY_OBJECT *gpo);
ADS_STATUS ads_search_retry_dn_sd_flags(ADS_STRUCT *ads, LDAPMessage **res,
					 uint32_t sd_flags,
					 const char *dn,
					 const char **attrs);
ADS_STATUS ads_do_search_all_sd_flags(ADS_STRUCT *ads, const char *bind_path,
				       int scope, const char *expr,
				       const char **attrs, uint32_t sd_flags,
				       LDAPMessage **res);
ADS_STATUS ads_get_tokensids(ADS_STRUCT *ads,
			      TALLOC_CTX *mem_ctx,
			      const char *dn,
			      struct dom_sid *user_sid,
			      struct dom_sid *primary_group_sid,
			      struct dom_sid **sids,
			      size_t *num_sids);
ADS_STATUS ads_get_joinable_ous(ADS_STRUCT *ads,
				TALLOC_CTX *mem_ctx,
				char ***ous,
				size_t *num_ous);

#endif /* _LIBADS_ADS_LDAP_PROTOS_H_ */
