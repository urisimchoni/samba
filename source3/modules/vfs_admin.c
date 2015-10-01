/*
 * admin VFS module. Fixes file ownership for files created by
 * an admin user in the share.
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

#include "../source3/include/includes.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "auth.h"

struct admin_data {
	uid_t orig_uid;
};

static bool is_admin(vfs_handle_struct *handle)
{
	return handle->conn->session_info->unix_token->uid == sec_initial_uid();
}

static void chown_object(vfs_handle_struct *handle,
			 const struct smb_filename *smb_fname)
{
	int rc;
	struct admin_data *ctx;

	SMB_VFS_HANDLE_GET_DATA(handle, ctx, struct admin_data, return );

	rc = SMB_VFS_LCHOWN(handle->conn, smb_fname, ctx->orig_uid, -1);
	DBG_DEBUG("Chowning '%s' to %u .. %s\n", smb_fname->base_name,
		  ctx->orig_uid, rc == 0 ? "OK" : strerror(errno));
}

static int admin_connect(vfs_handle_struct *handle, const char *service,
			 const char *user)
{
	int rc;
	struct admin_data *ctx;
	struct user_struct *vuser;

	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (rc < 0) {
		return rc;
	}

	ctx = talloc_zero(handle->conn, struct admin_data);
	if (!ctx) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	vuser = get_valid_user_struct(handle->conn->sconn, handle->conn->vuid);
	if (vuser == NULL) {
		DBG_ERR("No user found for vuid %llu\n",
			(unsigned long long)handle->conn->vuid);
		errno = EIO;
		return -1;
	}

	ctx->orig_uid = vuser->session_info->unix_token->uid;

	SMB_VFS_HANDLE_SET_DATA(handle, ctx, NULL, struct admin_data,
				return -1);
	return 0;
}

static int admin_mkdir(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname, mode_t mode)
{
	int rc = SMB_VFS_NEXT_MKDIR(handle, smb_fname, mode);
	if (is_admin(handle) && rc == 0) {
		chown_object(handle, smb_fname);
	}
	return rc;
}

static NTSTATUS
admin_create_file(struct vfs_handle_struct *handle, struct smb_request *req,
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
	NTSTATUS status;
	int info, rc;
	struct admin_data *ctx;

	status = SMB_VFS_NEXT_CREATE_FILE(
	    handle, req, root_dir_fid, smb_fname, access_mask, share_access,
	    create_disposition, create_options, file_attributes, oplock_request,
	    lease, allocation_size, private_flags, sd, ea_list, result, &info,
	    in_context_blobs, out_context_blobs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (pinfo) {
		*pinfo = info;
	}

	DBG_DEBUG("checking whether to fix owner of %s\n",
		  smb_fname_str_dbg(smb_fname));

	if (!is_admin(handle)) {
		DBG_DEBUG("not admin\n");
		return status;
	}

	if (info != FILE_WAS_CREATED) {
		DBG_DEBUG("not new - keep old owner\n");
		return status;
	}

	if ((*result)->is_directory) {
		DBG_DEBUG("directory - handled by mkdir\n");
		return status;
	}

	if ((*result)->fh->fd == -1) {
		DBG_DEBUG("no FD (a stream?)\n");
		return status;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, ctx, struct admin_data, return status);

	rc = SMB_VFS_FCHOWN(*result, ctx->orig_uid, -1);
	DBG_DEBUG("Chowning '%s' to %u .. %s\n", smb_fname_str_dbg(smb_fname),
		  ctx->orig_uid, rc == 0 ? "OK" : strerror(errno));

	return status;
}

static int admin_symlink(vfs_handle_struct *handle, const char *oldpath,
			 const char *newpath)
{
	int rc = SMB_VFS_NEXT_SYMLINK(handle, oldpath, newpath);
	if (is_admin(handle) && rc == 0) {
		/* we don't care much about the flags since
		   we use lchown unconditionally */
		struct smb_filename *new_smb_fname =
		    synthetic_smb_fname(talloc_tos(), newpath, NULL, NULL, 0);
		if (new_smb_fname == NULL) {
			DBG_ERR("cannot own new symlink at %s\n", newpath);
			return rc;
		}
		chown_object(handle, new_smb_fname);
		TALLOC_FREE(new_smb_fname);
	}
	return rc;
}

static int admin_mknod(vfs_handle_struct *handle, const char *path, mode_t mode,
		       SMB_DEV_T dev)
{
	int rc = SMB_VFS_NEXT_MKNOD(handle, path, mode, dev);
	if (is_admin(handle) && rc == 0) {
		struct smb_filename *smb_fname =
		    synthetic_smb_fname(talloc_tos(), path, NULL, NULL, 0);
		if (smb_fname == NULL) {
			DBG_ERR("cannot own new device node at %s\n", path);
			return rc;
		}
		chown_object(handle, smb_fname);
	}
	return rc;
}

/* VFS operations structure */

struct vfs_fn_pointers admin_fns = {
    /* Disk operations */

    .connect_fn = admin_connect,

    /* Directory operations */

    .mkdir_fn = admin_mkdir,

    /* File operations */

    /*	.open_fn = admin_open, */
    .create_file_fn = admin_create_file,
    .symlink_fn = admin_symlink,
    .mknod_fn = admin_mknod,
};

NTSTATUS vfs_admin_init(TALLOC_CTX *);
NTSTATUS vfs_admin_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "admin", &admin_fns);
}
