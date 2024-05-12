#pragma once

/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stdint.h>
#include <sys/capability.h>
#include <sys/types.h>

#include "macro.h"
#include "util.h"

#define CAP_ALL (uint64_t) -1

unsigned long cap_last_cap(void);
int capability_bounding_set_drop(uint64_t keep, bool right_now);

int drop_privileges(uid_t uid, gid_t gid, uint64_t keep_capabilities);

int drop_capability(cap_value_t cv);

DEFINE_TRIVIAL_CLEANUP_FUNC(cap_t, cap_free);
#define _cleanup_cap_free_ _cleanup_(cap_freep)

static inline void cap_free_charpp(char **p) {
        if (*p)
                cap_free(*p);
}
#define _cleanup_cap_free_charp_ _cleanup_(cap_free_charpp)

static inline bool cap_test_all(uint64_t caps) {
        uint64_t m;
        m = (UINT64_C(1) << (cap_last_cap() + 1)) - 1;
        return (caps & m) == m;
}
