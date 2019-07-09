/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_wrapper.c
 *
 * Implementation of system call "readv" and "writev".
 */

#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>
#include <shim_table.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

static int check_iovec(const struct iovec* vec, size_t vlen, bool write) {
    if (!vec || test_user_memory((void *) vec, sizeof(*vec) * vlen, false))
        return -EINVAL;

    for (size_t i = 0 ; i < vlen ; i++) {
        if (vec[i].iov_base) {
            if (vec[i].iov_base + vec[i].iov_len < vec[i].iov_base)
                return -EINVAL;
            if (test_user_memory(vec[i].iov_base, vec[i].iov_len, write))
                return -EFAULT;
        }
    }

    return 0;
}

loff_t set_handle_offset(struct shim_handle* hdl, loff_t new) {
    struct shim_mount * fs = hdl->fs;

    if (!fs || !fs->fs_ops)
        return -EACCES;

    if (!fs->fs_ops->seek)
        return -ESPIPE;

    if (hdl->type == TYPE_DIR)
        return -EACCES;

    loff_t old = fs->fs_ops->seek(hdl, 0, SEEK_CUR);
    if (old < 0)
        return old;

    loff_t ret = fs->fs_ops->seek(hdl, new, SEEK_SET);
    return (ret < 0) ? ret : old;
}

static ssize_t do_handle_readv(struct shim_handle* hdl, const struct iovec* vec, size_t vlen) {

    if (hdl->type == TYPE_DIR)
        return -EISDIR;

    if (!(hdl->acc_mode & MAY_READ) || !hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->read)
        return -EACCES;

    ssize_t bytes = 0;

    for (size_t i = 0 ; i < vlen ; i++) {
        int b_vec;

        if (!vec[i].iov_base)
            continue;

        b_vec = hdl->fs->fs_ops->read(hdl, vec[i].iov_base, vec[i].iov_len);
        if (b_vec < 0)
            return bytes ? : b_vec;
        bytes += b_vec;
    }

    return bytes;
}

ssize_t shim_do_readv(int fd, const struct iovec* vec, size_t vlen) {
    ssize_t ret = check_iovec(vec, vlen, true);
    if (ret < 0)
        return ret;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    ret = do_handle_readv(hdl, vec, vlen);
    put_handle(hdl);
    return ret;
}

/*
 * Writev can not be implemented as write because :
 * writev() has the same requirements as write() with respect to write requests
 * of <= PIPE_BUF bytes to a pipe or FIFO: no interleaving and no partial
 * writes. Neither of these can be guaranteed in the general case if writev()
 * simply calls write() for each struct iovec.
 */

/*
 * The problem here is that we have to gaurantee Atomic writev
 *
 * Upon successful completion, writev() shall return the number of bytes
 * actually written. Otherwise, it shall return a value of -1, the file-pointer
 * shall remain unchanged, and errno shall be set to indicate an error
 */
static ssize_t do_handle_writev(struct shim_handle* hdl, const struct iovec* vec, size_t vlen) {

    if (hdl->type == TYPE_DIR)
        return -EISDIR;

    if (!(hdl->acc_mode & MAY_WRITE) || !hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->write)
        return -EACCES;

    ssize_t bytes = 0;

    for (size_t i = 0 ; i < vlen ; i++) {
        int b_vec;

        if (!vec[i].iov_base)
            continue;

        b_vec = hdl->fs->fs_ops->write(hdl, vec[i].iov_base, vec[i].iov_len);
        if (b_vec < 0)
            return bytes ? : b_vec;
        bytes += b_vec;
    }

    return bytes;
}

ssize_t shim_do_writev(int fd, const struct iovec* vec, size_t vlen) {
    ssize_t ret = check_iovec(vec, vlen, false);
    if (ret < 0)
        return ret;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    ret = do_handle_writev(hdl, vec, vlen);
    put_handle(hdl);
    return ret;
}

ssize_t shim_do_preadv(int fd, const struct iovec* vec, size_t vlen, off_t pos_l, off_t pos_h) {

    loff_t pos = pos_l | ((loff_t) pos_h) << 32;
    if (pos < 0)
        return -EINVAL;

    ssize_t ret = check_iovec(vec, vlen, true);
    if (ret < 0)
        return ret;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    loff_t old_pos = set_handle_offset(hdl, pos);
    if (old_pos < 0) {
        ret = (ssize_t) old_pos;
        goto out;
    }

    ssize_t bytes = do_handle_readv(hdl, vec, vlen);

    loff_t new_pos = set_handle_offset(hdl, old_pos);
    if (new_pos < 0) {
        ret = (ssize_t) new_pos;
        goto out;
    }

    ret = bytes;
out:
    put_handle(hdl);
    return ret;
}

ssize_t shim_do_pwritev(int fd, const struct iovec* vec, size_t vlen, off_t pos_l, off_t pos_h) {
    loff_t pos = pos_l | ((loff_t) pos_h) << 32;
    if (pos < 0)
        return -EINVAL;

    ssize_t ret = check_iovec(vec, vlen, false);
    if (ret < 0)
        return ret;

    struct shim_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    loff_t old_pos = set_handle_offset(hdl, pos);
    if (old_pos < 0) {
        ret = (ssize_t) old_pos;
        goto out;
    }

    ssize_t bytes = do_handle_writev(hdl, vec, vlen);

    loff_t new_pos = set_handle_offset(hdl, old_pos);
    if (new_pos < 0) {
        ret = (ssize_t) new_pos;
        goto out;
    }

    ret = bytes;
out:
    put_handle(hdl);
    return ret;
}

