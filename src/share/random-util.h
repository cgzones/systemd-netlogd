/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

int dev_urandom(void *p, size_t n);
void random_bytes(void *p, size_t n);
void initialize_srand(void);

static inline uint64_t random_u64(void) {
        uint64_t u;
        random_bytes(&u, sizeof(u));
        return u;
}

static inline uint32_t random_u32(void) {
        uint32_t u;
        random_bytes(&u, sizeof(u));
        return u;
}
