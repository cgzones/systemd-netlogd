/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <alloca.h>
#include <stdbool.h>
#include <stddef.h>

#include "macro.h"
#include "time-util.h"

#define DEFAULT_PATH_NORMAL "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
#define DEFAULT_PATH_SPLIT_USR DEFAULT_PATH_NORMAL ":/sbin:/bin"

#ifdef HAVE_SPLIT_USR
#  define DEFAULT_PATH DEFAULT_PATH_SPLIT_USR
#else
#  define DEFAULT_PATH DEFAULT_PATH_NORMAL
#endif

bool is_path(const char *p) _pure_;
bool path_is_absolute(const char *p) _pure_;
char* path_kill_slashes(char *path);
char* path_startswith(const char *path, const char *prefix) _pure_;
int path_compare(const char *a, const char *b) _pure_;
bool path_equal(const char *a, const char *b) _pure_;

/* Note: the search terminates on the first NULL item. */
#define PATH_IN_SET(p, ...)                                     \
        ({                                                      \
                char **s;                                       \
                bool _found = false;                            \
                STRV_FOREACH(s, STRV_MAKE(__VA_ARGS__))         \
                        if (path_equal(p, *s)) {                \
                               _found = true;                   \
                               break;                           \
                        }                                       \
                _found;                                         \
        })

char** path_strv_resolve(char **l, const char *prefix);
char** path_strv_resolve_uniq(char **l, const char *prefix);

/* Iterates through the path prefixes of the specified path, going up
 * the tree, to root. Also returns "" (and not "/"!) for the root
 * directory. Excludes the specified directory itself */
#define PATH_FOREACH_PREFIX(prefix, path) \
        for (char *_slash = ({ path_kill_slashes(strcpy(prefix, path)); streq(prefix, "/") ? NULL : strrchr(prefix, '/'); }); _slash && ((*_slash = 0), true); _slash = strrchr((prefix), '/'))

/* Same as PATH_FOREACH_PREFIX but also includes the specified path itself */
#define PATH_FOREACH_PREFIX_MORE(prefix, path) \
        for (char *_slash = ({ path_kill_slashes(strcpy(prefix, path)); if (streq(prefix, "/")) prefix[0] = 0; strrchr(prefix, 0); }); _slash && ((*_slash = 0), true); _slash = strrchr((prefix), '/'))

char *prefix_root(const char *root, const char *path);

/* Similar to prefix_root(), but returns an alloca() buffer, or
 * possibly a const pointer into the path parameter */
#define prefix_roota(root, path)                                        \
        ({                                                              \
                const char* _path = (path), *_root = (root), *_ret;     \
                char *_p, *_n;                                          \
                size_t _l;                                              \
                while (_path[0] == '/' && _path[1] == '/')              \
                        _path ++;                                       \
                if (isempty(_root) || path_equal(_root, "/"))           \
                        _ret = _path;                                   \
                else {                                                  \
                        _l = strlen(_root) + 1 + strlen(_path) + 1;     \
                        _n = alloca(_l);                                \
                        _p = stpcpy(_n, _root);                         \
                        while (_p > _n && _p[-1] == '/')                \
                                _p--;                                   \
                        if (_path[0] != '/')                            \
                                *(_p++) = '/';                          \
                        strcpy(_p, _path);                              \
                        _ret = _n;                                      \
                }                                                       \
                _ret;                                                   \
        })

bool filename_is_valid(const char *p) _pure_;
bool path_is_safe(const char *p) _pure_;

char *file_in_same_dir(const char *path, const char *filename);

bool hidden_or_backup_file(const char *filename) _pure_;
