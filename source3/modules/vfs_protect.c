/*
 * protect VFS module. Protects a pre-configured list of directories
 * from deletion/rename
 *
 * Copyright (C) Uri Simchoni, 2015
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"

/* this module protects paths from deletion/renaming */
struct protect_module_data {
	char **protected_paths;
};

static int protect_connect(vfs_handle_struct *handle, const char *service,
			   const char *user)
{
	struct protect_module_data *mod_data;
	int ret;

	mod_data = talloc_zero(handle->conn, struct protect_module_data);
	if (mod_data == NULL) {
		errno = ENOMEM;
		return -1;
	}

	SMB_VFS_HANDLE_SET_DATA(handle, mod_data, NULL,
				struct protect_module_data, return -1);

	mod_data->protected_paths = str_list_copy(
	    mod_data,
	    lp_parm_string_list(SNUM(handle->conn), "protect", "dirs", NULL));

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);

	return ret;
}

static bool path_is_protected(const char *path,
			      const struct protect_module_data *mod_data)
{
	char **ppath = mod_data->protected_paths;
	if (!ppath)
		return false;
	while (*ppath) {
		if (strcsequal(*ppath, path)) {
			return true;
		}
		++ppath;
	}

	return false;
}

static int protect_rmdir(vfs_handle_struct *handle,
			 const struct smb_filename *smb_fname)
{
	struct protect_module_data *mod_data;
	SMB_VFS_HANDLE_GET_DATA(handle, mod_data, struct protect_module_data,
				return -1);
	if (path_is_protected(smb_fname->base_name, mod_data)) {
		errno = EPERM;
		return -1;
	}

	return SMB_VFS_NEXT_RMDIR(handle, smb_fname);
}

static int protect_rename(vfs_handle_struct *handle,
			  const struct smb_filename *oldname,
			  const struct smb_filename *newname)
{
	struct protect_module_data *mod_data;
	SMB_VFS_HANDLE_GET_DATA(handle, mod_data, struct protect_module_data,
				return -1);
	if (path_is_protected(oldname->base_name, mod_data) ||
	    path_is_protected(newname->base_name, mod_data)) {
		errno = EPERM;
		return -1;
	}

	return SMB_VFS_NEXT_RENAME(handle, oldname, newname);
}

static NTSTATUS
protect_create_file(struct vfs_handle_struct *handle, struct smb_request *req,
		    uint16_t root_dir_fid, struct smb_filename *smb_fname,
		    uint32_t access_mask, uint32_t share_access,
		    uint32_t create_disposition, uint32_t create_options,
		    uint32_t file_attributes, uint32_t oplock_request,
		    struct smb2_lease *lease, uint64_t allocation_size,
		    uint32_t private_flags, struct security_descriptor *sd,
		    struct ea_list *ea_list, files_struct **result, int *pinfo,
		    const struct smb2_create_blobs *in_context_blobs,
		    struct smb2_create_blobs *out_context_blobs)
{
	struct protect_module_data *mod_data;

	if ((access_mask & DELETE_ACCESS) == 0) {
		/* No chance of delete / rename */
		goto create;
	}

	if ((create_options & FILE_NON_DIRECTORY_FILE) != 0) {
		/* not a dir (if the actual object is a dir,
		 * the server will fail it)
		 */
		goto create;
	}

	/*
	 * Object *might* be a directory and the user
	 * *might* want to delete it - fail the open
	 * if it's a protected path.
	 *
	 * We have no way of failing the delete only
	 * if it's actually intended (setting the delete-
	 * on-close flag), but clients usually don't just
	 * ask dor DELETE access without intent to later
	 * delete the file.
	 */
	SMB_VFS_HANDLE_GET_DATA(handle, mod_data, struct protect_module_data,
				return NT_STATUS_UNSUCCESSFUL);
	if (path_is_protected(smb_fname->base_name, mod_data)) {
		return NT_STATUS_ACCESS_DENIED;
	}

create:
	return SMB_VFS_NEXT_CREATE_FILE(
	    handle, req, root_dir_fid, smb_fname, access_mask, share_access,
	    create_disposition, create_options, file_attributes, oplock_request,
	    lease, allocation_size, private_flags, sd, ea_list, result, pinfo,
	    in_context_blobs, out_context_blobs);
}

/* VFS operations structure */

static struct vfs_fn_pointers protect_fns = {
    .connect_fn = protect_connect,
    .rmdir_fn = protect_rmdir,
    .rename_fn = protect_rename,
    .create_file_fn = protect_create_file,
};

NTSTATUS vfs_protect_init(TALLOC_CTX *);
NTSTATUS vfs_protect_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "protect",
				&protect_fns);
}
