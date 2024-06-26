/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdint.h>
#include <stdlib.h>

#include "macro.h"
#include "mempool.h"
#include "util.h"

struct pool {
        struct pool *next;
        unsigned n_tiles;
        unsigned n_used;
};

void* mempool_alloc_tile(struct mempool *mp) {
        unsigned i;

        /* When a tile is released we add it to the list and simply
         * place the next pointer at its offset 0. */

        assert(mp->tile_size >= sizeof(void*));
        assert(mp->at_least > 0);

        if (mp->freelist) {
                void *r;

                r = mp->freelist;
                mp->freelist = * (void**) mp->freelist;
                return r;
        }

        if (_unlikely_(!mp->first_pool) ||
            _unlikely_(mp->first_pool->n_used >= mp->first_pool->n_tiles)) {
                unsigned n;
                size_t size;
                struct pool *p;

                n = mp->first_pool ? mp->first_pool->n_tiles : 0;
                n = MAX(mp->at_least, n * 2);
                size = PAGE_ALIGN(ALIGN(sizeof(struct pool)) + n*mp->tile_size);
                n = (size - ALIGN(sizeof(struct pool))) / mp->tile_size;

                p = malloc(size);
                if (!p)
                        return NULL;

                p->next = mp->first_pool;
                p->n_tiles = n;
                p->n_used = 0;

                mp->first_pool = p;
        }

        i = mp->first_pool->n_used++;

        return ((uint8_t*) mp->first_pool) + ALIGN(sizeof(struct pool)) + i*mp->tile_size;
}

void* mempool_alloc0_tile(struct mempool *mp) {
        void *p;

        p = mempool_alloc_tile(mp);
        if (p)
                memzero(p, mp->tile_size);
        return p;
}

void mempool_free_tile(struct mempool *mp, void *p) {
        * (void**) p = mp->freelist;
        mp->freelist = p;
}
