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

#ifndef _FLOWTABLE_H
#define _FLOWTABLE_H

#include "flow.h"
#include <unistd.h>

/*
 * Entry of flow table
 */
typedef struct {
    /* Valid */
    uint8_t valid;
    /* Key */
    flow_t flow;
    /* Value */
    flow_stats_t stat;
} flowtable_entry_t;

/*
 * Flow table
 */
typedef struct {
    /* Flow table size */
    size_t size;
    /* Entries; i.e., buckets of a hash table */
    flowtable_entry_t *entries;
} flowtable_t;

/* Callback function for flowtable_scal() */
typedef int (*flowtable_scan_f)(flowtable_t *, flowtable_entry_t *);

#ifdef __cplusplus
extern "C" {
#endif

    flowtable_t * flowtable_init(size_t);
    void flowtable_release(flowtable_t *);
    flow_stats_t * flowtable_search(flowtable_t *, flow_t *);
    int flowtable_scan_cb(flowtable_t *, flowtable_scan_f);
    int flowtable_reset(flowtable_t *);

#ifdef __cplusplus
}
#endif

#endif /* _FLOWTABLE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
