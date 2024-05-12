/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <sys/types.h>

int mkdir_safe(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_parents(const char *path, mode_t mode);
int mkdir_p(const char *path, mode_t mode);

/* mandatory access control(MAC) versions */
int mkdir_safe_label(const char *path, mode_t mode, uid_t uid, gid_t gid);
int mkdir_parents_label(const char *path, mode_t mode);
int mkdir_p_label(const char *path, mode_t mode);

/* internally used */
typedef int (*mkdir_func_t)(const char *pathname, mode_t mode);
int mkdir_safe_internal(const char *path, mode_t mode, uid_t uid, gid_t gid, mkdir_func_t _mkdir);
int mkdir_parents_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir);
int mkdir_p_internal(const char *prefix, const char *path, mode_t mode, mkdir_func_t _mkdir);
