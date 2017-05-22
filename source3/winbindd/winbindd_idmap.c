/*
   Unix SMB/CIFS implementation.

   Async helpers for blocking functions

   Copyright (C) Volker Lendecke 2005
   Copyright (C) Gerald Carter 2006
   Copyright (C) Simo Sorce 2007

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
#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

static void init_idmap_process_done(struct tevent_req *req);
static struct winbindd_child static_idmap_child;

static void idmap_child_on_process_init(struct winbindd_child *child)
{
	struct winbindd_domain *domain;
	struct tevent_req *req;

	/* initialize all domains we already know of.
	 * newly-added domains will be initialized
	 * as they are added
	 */
	for (domain = domain_list(); domain != NULL; domain = domain->next) {
		req =
		    wb_init_idmap_backend_send(domain, winbind_event_context(),
					       domain->name, &domain->sid);
		if (!req) {
			smb_panic(
			    "failed calling idmap child to initialize backend");
		}
		tevent_req_set_callback(req, init_idmap_process_done, domain);
	}
}

static void init_idmap_process_done(struct tevent_req *req)
{
	struct winbindd_domain *domain =
	    tevent_req_callback_data(req, struct winbindd_domain);
	NTSTATUS status;
	bool require_sid_type = true;

	status = wb_init_idmap_backend_recv(req, &require_sid_type);
	TALLOC_FREE(req);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("Failed initializing idmap for domain %s\n",
			    domain->name);
		return;
	}

	DBG_DEBUG("Domain %s id-mapping %s sid type\n", domain->name,
		  require_sid_type ? "requires" : "does not require");
	domain->idmap_require_sid_type = require_sid_type;
}

struct winbindd_child *idmap_child(void)
{
	return &static_idmap_child;
}

static const struct winbindd_child_dispatch_table idmap_dispatch_table[] = {
	{
		.name		= "PING",
		.struct_cmd	= WINBINDD_PING,
		.struct_fn	= winbindd_dual_ping,
	},{
		.name		= "NDRCMD",
		.struct_cmd	= WINBINDD_DUAL_NDRCMD,
		.struct_fn	= winbindd_dual_ndrcmd,
	},{
		.name		= NULL,
	}
};

void init_idmap_child(void)
{
	setup_child(NULL, &static_idmap_child,
		    idmap_dispatch_table,
		    idmap_child_on_process_init,
		    "log.winbindd", "idmap");
}
