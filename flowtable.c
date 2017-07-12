/*_
 * Copyright (c) 2017 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "flowtable.h"
#include <stdlib.h>
#include <string.h>

/*
 * Jenkins Hash Function
 */
static __inline__ uint32_t
_jenkins_hash(uint8_t *key, size_t len)
{
    uint32_t hash;
    size_t i;

    hash = 0;
    for ( i = 0; i < len; i++ ) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

/*
 * Initialize a flow table
 */
flowtable_t *
flowtable_init(size_t size)
{
    flowtable_t *ft;

    /* Allocate the management data structure */
    ft = malloc(sizeof(flowtable_t));
    if ( NULL == ft ) {
        return NULL;
    }
    ft->entries = malloc(sizeof(flowtable_entry_t) * size);
    if ( NULL == ft->entries ) {
        free(ft);
        return NULL;
    }
    ft->size = size;

    return ft;
}

/*
 * Release a flow table
 */
void
flowtable_release(flowtable_t *ft)
{
    free(ft->entries);
    free(ft);
}

/*
 * Search a flow corresponding to the specified key from flow table
 */
flow_stats_t *
flowtable_search(flowtable_t *ft, flow_t *f)
{
    ssize_t i;
    uint32_t hash;

    /* Compute hash value of the flow */
    hash = _jenkins_hash((void *)f, sizeof(flow_t));
    hash = hash % ft->size;

    /* Linear probing */
    for ( i = 0; i < (ssize_t)ft->size; i++ ) {
        if ( ft->entries[hash].valid ) {
            if ( 0 == memcmp(f, &ft->entries[hash].flow, sizeof(flow_t)) ) {
                return &ft->entries[hash].stat;
            }
        } else {
            /* Not found, then create new entry */
            ft->entries[hash].valid = 1;
            (void)memcpy(&ft->entries[hash],f, sizeof(flow_t));
            (void)memset(&ft->entries[hash].stat, 0, sizeof(flow_stats_t));
            return &ft->entries[hash].stat;
        }

        /* Next bucket */
        hash = hash + 1 < ft->size ? hash + 1 : 0;
    }

    /* Not found, and the table is full */
    return NULL;
}

/*
 * Scan all the entries with a callback function
 */
int
flowtable_scan_cb(flowtable_t *ft, flowtable_scan_f cb)
{
    ssize_t i;

    for ( i = 0; i < (ssize_t)ft->size; i++ ) {
        cb(ft, &ft->entries[i]);
    }

    return 0;
}

/*
 * Reset the flow table
 */
int
flowtable_reset(flowtable_t *ft)
{
    (void)memset(ft->entries, 0, sizeof(flowtable_entry_t) * ft->size);

    return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
