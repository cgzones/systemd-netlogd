/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>

#include "macro.h"

/* Make sure we can distinguish fd 0 and NULL */
#define FD_TO_PTR(fd) INT_TO_PTR((fd)+1)
#define PTR_TO_FD(p) (PTR_TO_INT(p)-1)

int close_nointr(int fd);
int safe_close(int fd);

void close_many(const int fds[], unsigned n_fd);

int fclose_nointr(FILE *f);
FILE* safe_fclose(FILE *f);

static inline void closep(int *fd) {
        safe_close(*fd);
}

static inline void fclosep(FILE **f) {
        safe_fclose(*f);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(FILE*, pclose);
DEFINE_TRIVIAL_CLEANUP_FUNC(DIR*, closedir);

#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)
#define _cleanup_close_pair_ _cleanup_(close_pairp)

int fd_cloexec(int fd, bool cloexec);
int fd_nonblock(int fd, bool nonblock);
void stdio_unset_cloexec(void);



void cmsg_close_all(struct msghdr *mh);


/* Hint: ENETUNREACH happens if we try to connect to "non-existing" special IP addresses, such as ::5 */
#define ERRNO_IS_DISCONNECT(r) \
        IN_SET(r, ENOTCONN, ECONNRESET, ECONNREFUSED, ECONNABORTED, EPIPE, ENETUNREACH)
